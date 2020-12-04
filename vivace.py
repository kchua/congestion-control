import socket
import json
import optparse
import select
import random
import time as t
import heapq

import numpy as np
import logging
logging.basicConfig(format='[%(asctime)s.%(msecs)03d] CLIENT - %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S', filename='network.log', level=logging.DEBUG)


IS_SYN         = 0x1
IS_FIN         = 0x2
IS_ACK         = 0x4
IS_RESET       = 0x8
SACK_PERMITTED = 0x10
IS_SACK        = 0x20

MAX_PACKET_SIZE = 10
MAX_RETRANSMIT  = 50
ALPHA = 0.9


def create_packet(seqnum, acknum, data, rwnd, flags):
    return {
        'seqnum': seqnum,
        'acknum': acknum,
        'data':   data,
        'rwnd':   rwnd,
        'flags':  flags,
    }


READ_FLAGS = select.POLLIN | select.POLLPRI
WRITE_FLAGS = select.POLLOUT
ERR_FLAGS = select.POLLERR | select.POLLHUP | select.POLLNVAL
READ_ERR_FLAGS = READ_FLAGS | ERR_FLAGS
ALL_FLAGS = READ_FLAGS | WRITE_FLAGS | ERR_FLAGS

# State flags
CLOSED = 1
LISTEN = 2
SYN_SENT = 3
SYN_RCVD = 4
ESTABLISHED = 5

# Vivace state flags
WAITING_FIRST_SRTT = -1
SLOW_START = 0
USING_BASE_RATE = 1
TESTING_HIGHER = 2
TESTING_LOWER = 3
WAITING_RESULTS = 4

VIVACE_STATE = {
    -1: "WAITING FOR FIRST SRTT",
    0 : "SLOW START",
    1 : "USING BASE RATE",
    2 : "TESTING HIGHER RATE",
    3 : "TESTING LOWER RATE",
    4 : "WAITING FOR MI GROUP RESULTS"
}

# Vivace constants
VIVACE_EPS = 0.05
BNDRY = 0.05
BNDRY_STEP = 0.1

class Client:
    def __init__(self, server, read_data):
        """
        Creates a client which will attempt to connect to
        the server determined by the (ip, port) tuple in the
        server argument.
        """

        # Connection that will be initialized once.
        self.server = server  # Server identified with an (ip, port) pair.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.poller = select.poll()
        self.poller.register(self.sock, ALL_FLAGS)
        self.read_data = read_data

        # TCP State that will be updated throughout the run.
        self.state = CLOSED
        self.our_seq = random.randrange(1024)  # The current sequence number on our side.
        self.ack_seq = -1  # The sequence number we have acknowledged.
        self.retransmit_count = 0  # Number of times has our last message been retransmitted.

        # Contains {timestamp, packet, retransmitted, ACKed}. Retransmits will happen upon timeout.
        # We can also use this to set estimated RTT, when retransmitted = False.
        self.packets_in_flight = []
        self.in_flight_dict = {}
        self.retransmit_queue = []
        self.has_estimated_rtt = False
        self.estimated_rtt = 1.0  # in seconds
        self.rto = np.inf
        self.time_since_transmit = 0.0

        self.vivace_state = WAITING_FIRST_SRTT
        self.vivace_cur_start_MI = None
        self.MI_info_list = []
        self.cur_rate = 1.0
        self.base_rate = 1.0
        self.times_exceeded_boundary = 0
        self.num_same_sign_steps = 0

        self.past_MI_utilities = []
        self.past_MI_rates = []

    def syn_packet(self):
        return create_packet(self.our_seq, 0, "", 0, IS_SYN | SACK_PERMITTED)

    def ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK)

    def send_packet(self, packet):
        self.sock.sendto(
            json.dumps(packet).encode(),
            self.server
        )

    def update_rtt(self, srtt):
        if self.has_estimated_rtt:
            self.estimated_rtt = self.estimated_rtt * ALPHA + srtt * (1.0 - ALPHA)
        else:
            self.estimated_rtt = srtt
            self.has_estimated_rtt = True
            self.cur_rate = 10.0 / self.estimated_rtt
            logging.debug("Estimated RTT for the first time. Set sending rate to {}".format(self.cur_rate))
        self.rto = 4 * self.estimated_rtt
        # logging.debug('Updated RTT {}'.format(self.estimated_rtt))

    @property
    def cur_MI(self):
        return None if len(self.MI_info_list) == 0 else self.MI_info_list[-1]

    def start_new_MI(self):
        self.MI_info_list.append({
            'idx': 0 if self.cur_MI is None else self.cur_MI["idx"] + 1,
            'start': t.time(),
            'rtt': self.estimated_rtt,
            'rate': self.cur_rate,
            'packet_srtts': [],
            'packet_acks': [],
            'times': [],
            'utility': np.inf,
        })
        self.time_since_transmit = 0    # Want to transmit right away.

    def finalize_MIs_before(self, idx):
        """Computes the utility function for MIs with index
        smaller than idx
        (Assumption: If an ACK or SACK arrives for a particular MI, anything
        missing before that MI that was not ACKed are assumed lost)
        """
        true_idx = idx - self.MI_info_list[0]['idx']
        if true_idx < 0:
            logging.debug("Monitor interval flushed before SACK arrived.")
        if true_idx > len(self.MI_info_list):
            raise IndexError("Invalid index.")
        for i in range(true_idx):
            rtt = self.MI_info_list[i]['rtt']
            rate = self.MI_info_list[i]['rate']
            srtts = np.array(self.MI_info_list[i]['packet_srtts'])
            acks = np.array(self.MI_info_list[i]['packet_acks'])
            times = np.array(self.MI_info_list[i]['times'])

            if len(srtts) == 0:
                self.MI_info_list[i]['utility'] = rate ** 0.9
            else:
                lost_packets = np.isinf(srtts)
                srtts = srtts[np.logical_not(lost_packets)]
                times = times[np.logical_not(lost_packets)]

                loss_rate = float(len(acks) - np.count_nonzero(acks)) / float(len(acks))
                if len(srtts) > 2:
                    mean_srtt, mean_time = np.mean(srtts), np.mean(times)
                    srtt_devs, time_devs = srtts - mean_srtt, times - mean_time
                    weights = time_devs / np.sum(time_devs ** 2)
                    latency_change = np.sum(srtt_devs * weights)
                else:
                    latency_change = 0  # TODO: What is the appropriate value if all packets are lost?
                self.MI_info_list[i]['utility'] = (rate ** 0.9) - (900 * rate * latency_change) - (11.35 * rate * loss_rate)

            self.past_MI_rates.append(rate)
            self.past_MI_utilities.append(self.MI_info_list[i]['utility'])

            logging.debug("########################################################")
            logging.debug("New MI reported.")
            logging.debug("MI #{}".format(self.MI_info_list[i]['idx']))
            logging.debug("Packets sent: {}".format(len(acks)))
            logging.debug("Sending rate: {}".format(rate))
            logging.debug("Latency change: {}".format(latency_change))
            logging.debug("Loss rate: {}".format(loss_rate))
            logging.debug("Utility: {}".format(self.MI_info_list[i]['utility']))
            logging.debug("########################################################\n")
        self.MI_info_list = self.MI_info_list[true_idx:]

    def run(self):
        while True:
            if self.state == CLOSED:
                # Initialize random sequence number.
                self.retransmit_count = 0
                self.our_seq = random.randrange(1024)
                self.sock.setblocking(0)
                self.poller.modify(self.sock, READ_ERR_FLAGS)
                logging.info("Attempting handshake.")

                # Create and send SYN packet.
                self.send_packet(self.syn_packet())
                self.state = SYN_SENT
                self.time_since_transmit = t.time()

            elif self.state == LISTEN:
                pass
            elif self.state == SYN_SENT:
                events = self.poller.poll(1000)  # Poll for one second

                ack_received = False
                # We have received something. Parse it.
                for fd, flag in events:
                    assert self.sock.fileno() == fd

                    if flag & ERR_FLAGS:
                        logging.error('Error flags set.')
                        self.state = CLOSED
                        return
                    if flag & READ_FLAGS:
                        msg, addr = self.sock.recvfrom(1600)
                        decoded_msg = json.loads(msg.decode())

                        if addr != self.server:
                            logging.warn('Received packet from identified server.')
                            continue

                        if (decoded_msg['flags'] & IS_SYN) and (decoded_msg['flags'] & IS_ACK):
                            if decoded_msg['acknum'] == self.our_seq + 1:
                                if self.retransmit_count == 0:
                                    self.update_rtt(t.time() - self.time_since_transmit)

                                ack_received = True
                                self.ack_seq = decoded_msg['seqnum']
                                self.retransmit_count = 0
                                logging.info('Received SYN-ACK for Client Seq {} Server Seq {}'.format(self.our_seq, self.ack_seq))

                                self.send_packet(self.ack_packet())
                                self.state = ESTABLISHED
                                logging.info('Connection established for Client.')

                                self.time_since_transmit = 0.0

                # If events is empty, retransmit or fail.
                if not events or not ack_received:
                    self.retransmit_count += 1

                    if self.retransmit_count > MAX_RETRANSMIT:
                        logging.error("Exceeded {} attempts. Giving up.".format(MAX_RETRANSMIT))
                        self.state = CLOSED
                        return

                    # Do the retransmission.
                    self.send_packet(self.syn_packet())
                    logging.warn("Retrying SYN packet.")
            elif self.state == SYN_RCVD:
                pass
            elif self.state == ESTABLISHED:
                # Check if we have any new ACKs
                while True:
                    try:
                        msg, addr = self.sock.recvfrom(1600)
                        received = t.time()
                        sacked_infodict = None
                        decoded_msg = json.loads(msg.decode())

                        if decoded_msg['flags'] & IS_SACK:
                            sack_left, sack_right = decoded_msg['sack_left'], decoded_msg['sack_right']
                            if self.in_flight_dict.has_key(sack_left):
                                infodict = self.in_flight_dict[sack_left]
                                assert sack_right == self._end_seqnum(infodict['packet']) + 1

                                infodict['ACKed'] = True
                                del self.in_flight_dict[sack_left]
                                # if not infodict['retransmitted']:
                                self.update_rtt(received - infodict['timestamp'])
                                sacked_infodict = infodict

                        if decoded_msg['flags'] & IS_ACK:
                            ack_num = decoded_msg['acknum']

                            while len(self.packets_in_flight) > 0:
                                if self.packets_in_flight[0][1]['ACKed']:
                                    heapq.heappop(self.packets_in_flight)
                                elif self._end_seqnum(self.packets_in_flight[0][1]['packet']) < ack_num:
                                    infodict = heapq.heappop(self.packets_in_flight)[1]

                                    infodict['ACKed'] = True
                                    del self.in_flight_dict[infodict['packet']['seqnum']]
                                    # Do not use an ACK to update RTT - should have received a SACK.

                                    # Do stuff with monitoring
                                    self.on_ack(infodict, received)
                                else:
                                    break

                        if sacked_infodict is not None:
                            self.on_ack(sacked_infodict, received, is_SACK=True)
                    except socket.error as e:
                        # No packet
                        break

                self.cc_update()

                # Check if we should transmit a packet.
                if t.time() - self.time_since_transmit > 1.0 / self.cur_rate:
                    # Check if there are outstanding unACKed packets to retransmit.
                    infodict = None
                    while len(self.retransmit_queue) > 0 and t.time() > self.retransmit_queue[0][0] + self.rto:
                        if self.retransmit_queue[0][1]['ACKed']:
                            heapq.heappop(self.retransmit_queue)
                        else:
                            infodict = heapq.heappop(self.retransmit_queue)[1]
                            infodict['retransmitted'] = True
                            logging.debug('Retransmitting packet with data {}'.format(
                                infodict['packet']['data'])
                            )
                            self.rto *= 2
                            break

                    # No packets to retransmit this time, send a new one if possible.
                    if infodict is None:
                        data = self.read_data(MAX_PACKET_SIZE)
                        if len(data) > 0:
                            packet = create_packet(self.our_seq + 1, self.ack_seq + 1, data, 0, IS_ACK)
                            self.our_seq += len(data)
                            infodict = {
                                'packet': packet,
                                'retransmitted': False,
                                'ACKed': False
                            }
                            self.in_flight_dict[packet['seqnum']] = infodict
                            heapq.heappush(self.packets_in_flight, (packet['seqnum'], infodict))

                        elif len(self.packets_in_flight) == 0:
                            logging.info('Finished transmitting all data.')
                            self.state = CLOSED
                            return

                    # If there is something to send
                    if infodict is not None:
                        self.send_packet(infodict['packet'])
                        self.time_since_transmit = t.time()
                        infodict['timestamp'] = self.time_since_transmit
                        heapq.heappush(self.retransmit_queue, (self.time_since_transmit, infodict))
                        self.on_send(infodict, self.time_since_transmit)

            else:
                logging.error('Incorrect TCP State.')
                self.state = CLOSED
                return

    def on_ack(self, infodict, received, is_SACK=False):
        if infodict.has_key('MI'):
            mntr_itval, itval_idx = infodict['MI'], infodict['MI_idx']
            mntr_itval['packet_acks'][itval_idx] = True
            if is_SACK:
                mntr_itval['packet_srtts'][itval_idx] = received - infodict['timestamp']
                self.finalize_MIs_before(mntr_itval['idx'])

    def cc_update(self):
        # Vivace monitor handling and rate control
        if self.has_estimated_rtt and self.cur_MI is None:
            self.vivace_state = SLOW_START
        if self.vivace_state != WAITING_FIRST_SRTT:
            if self.cur_MI is None:
                self.start_new_MI()
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                logging.debug("Started a new monitor interval.")
                logging.debug("MI #{}".format(self.cur_MI['idx']))
                logging.debug("Sending rate: {}".format(self.cur_MI['rate']))
                logging.debug("Current RTT estimate: {}s.".format(self.cur_MI['rtt']))
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
            elif t.time() - self.cur_MI["start"] > self.cur_MI["rtt"]:
                if self.vivace_state == SLOW_START:
                    if len(self.past_MI_utilities) >= 2 and self.past_MI_utilities[-1] < self.past_MI_utilities[-2]:
                        self.cur_rate = self.past_MI_rates[-2]
                        self.base_rate = self.cur_rate
                        self.vivace_state = USING_BASE_RATE
                        self.vivace_cur_start_MI = self.cur_MI['idx'] + 1
                        logging.debug("Exiting out of slow start phase.")
                    else:
                        self.cur_rate *= 2.0
                elif self.vivace_state == USING_BASE_RATE:                # Switch to testing r(1 + e)
                    self.cur_rate = (1.0 + VIVACE_EPS) * self.base_rate
                    self.vivace_state = TESTING_HIGHER
                elif self.vivace_state == TESTING_HIGHER:
                    self.cur_rate = (1.0 - VIVACE_EPS) * self.base_rate      # Switch to testing r(1 - e)
                    self.vivace_state = TESTING_LOWER
                elif self.vivace_state == TESTING_LOWER:
                    self.cur_rate = self.base_rate                        # Reset to base rate until we get results.
                    self.vivace_state = WAITING_RESULTS
                elif self.vivace_state == WAITING_RESULTS:
                    if len(self.past_MI_utilities) > self.vivace_cur_start_MI + 3:   # Once we get results
                        idx = self.vivace_cur_start_MI
                        util_diff = (self.past_MI_utilities[idx + 1] - self.past_MI_utilities[idx + 2])
                        est_grad = util_diff / (2 * VIVACE_EPS * self.base_rate)

                        # Compute step size and gradient step
                        if est_grad * self.num_same_sign_steps < 0:
                            self.num_same_sign_steps = 0
                            self.times_exceeded_boundary = 0
                        step_size = np.maximum(1, np.maximum(self.num_same_sign_steps, 2 * self.num_same_sign_steps - 3))
                        grad_step = est_grad * step_size
                        self.num_same_sign_steps += int(np.sign(grad_step))

                        # Compute bound on grad step
                        boundary = self.base_rate * (BNDRY + self.times_exceeded_boundary * BNDRY_STEP)
                        if np.abs(grad_step) > boundary:
                            grad_step = boundary * float(np.sign(grad_step))
                            self.times_exceeded_boundary += 1
                        else:
                            # Smallest value for this so that boundary is larger than grad_step
                            self.times_exceeded_boundary = int(((np.abs(grad_step) / self.base_rate) - BNDRY) / BNDRY_STEP) + 1
                        print(grad_step)

                        self.base_rate = self.base_rate + grad_step                                # Compute a new base rate
                        self.cur_rate = self.base_rate
                        self.vivace_state = USING_BASE_RATE
                        self.vivace_cur_start_MI = self.cur_MI['idx'] + 1

                self.start_new_MI()
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                logging.debug("Started a new monitor interval.")
                logging.debug("MI #{}".format(self.cur_MI['idx']))
                logging.debug("Sending rate: {}".format(self.cur_MI['rate']))
                logging.debug("Current RTT estimate: {}s.".format(self.cur_MI['rtt']))

                if self.vivace_state != SLOW_START:
                    logging.debug("")
                    logging.debug("MI is part of experiment group that started with MI #{}.".format(self.vivace_cur_start_MI))
                    logging.debug("Current state: {}".format(VIVACE_STATE[self.vivace_state]))
                    logging.debug("Experiment group base rate: {}".format(self.base_rate))
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

    def on_send(self, infodict, time_sent):
        if self.vivace_state != WAITING_FIRST_SRTT:
            infodict.update({
                'MI': self.cur_MI,
                'MI_idx': len(self.cur_MI['packet_srtts'])
            })
            self.cur_MI['packet_srtts'].append(np.inf)
            self.cur_MI['packet_acks'].append(False)
            self.cur_MI['times'].append(time_sent - self.cur_MI['start'])

    @staticmethod
    def _end_seqnum(packet):
        return packet['seqnum'] + len(packet['data']) - 1


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-i', dest='ip', default='127.0.0.1')
    parser.add_option('-p', dest='port', type='int', default=12345)
    (options, args) = parser.parse_args()

    lipsum = open('lipsum.txt', 'r')
    def read_data(num_chars):
        data = lipsum.read(num_chars)
        return data

    client = Client((options.ip, options.port), read_data)
    client.run()
    lipsum.close()
