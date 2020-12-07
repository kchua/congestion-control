from __future__ import division

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

MAX_DATA_SIZE = 1400
MAX_RETRANSMIT  = 50
ALPHA = 0.9

LATENCY_AWARE = True

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

# Allegro state flags
WAITING_FIRST_SRTT = -1
SLOW_START = 0
DECISION_STATE = 1
RATE_ADJUSTING_STATE = 2
WAITING_RESULTS = 3

ALLEGRO_STATE = {
    -1: "WAITING FOR FIRST SRTT",
    0 : "SLOW START",
    1 : "DECISION STATE",
    2 : "RATE ADJUSTING STATE",
    3 : "WAITING FOR MI GROUP RESULTS"
}


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
        self.has_estimated_rtt = False
        self.estimated_rtt = 1.0  # in seconds
        self.rto = np.inf
        self.time_since_transmit = 0.0
        self.time_to_retransmit = np.inf

        self.allegro_state = WAITING_FIRST_SRTT
        self.rct_ordering = (1, -1, 1, -1)
        self.rct_idx = 0  # Which MI of the randomized control trial are we on.
        self.decided_direction = 0
        self.experiment_granularity = 0.01
        self.max_granularity = 0.05
        self.eps_delta = 0.01

        self.allegro_cur_start_MI = None
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
            return
        if true_idx > len(self.MI_info_list):
            raise IndexError("Invalid index.")
        for i in range(true_idx):
            rtt = self.MI_info_list[i]['rtt']
            rate = self.MI_info_list[i]['rate']
            past_srtts = np.array(self.MI_info_list[i-1]['packet_srtts'])
            srtts = np.array(self.MI_info_list[i]['packet_srtts'])
            acks = np.array(self.MI_info_list[i]['packet_acks'])
            times = np.array(self.MI_info_list[i]['times'])

            if len(srtts) == 0:
                self.MI_info_list[i]['utility'] = rate ** 0.9
                loss_rate = None
                throughput = 0.0
                rtt_now = 0.0
            else:
                rtt_now = np.mean(srtts[np.isfinite(srtts)])
                rtt_before = np.mean(past_srtts[np.isfinite(past_srtts)])
                loss_rate = float(len(acks) - np.count_nonzero(acks)) / float(len(acks))
                throughput = rate * (1 - loss_rate)

                alpha = 100
                beta = 10
                sigmoid_loss = 1.0 / (1.0 + np.exp(alpha * (loss_rate - 0.05)))
                if LATENCY_AWARE and rtt_now > 0:
                    sigmoid_latency = 1.0 / (1.0 + np.exp(beta * (rtt_before / rtt_now - 1)))
                    self.MI_info_list[i]['utility'] = (throughput * sigmoid_loss * sigmoid_latency - rate * loss_rate) / rtt_now
                else:
                    self.MI_info_list[i]['utility'] = throughput * sigmoid_loss - rate * loss_rate

            self.past_MI_rates.append(rate)
            self.past_MI_utilities.append(self.MI_info_list[i]['utility'])

            logging.debug("########################################################")
            logging.debug("New MI reported.")
            logging.debug("MI #{}".format(self.MI_info_list[i]['idx']))
            logging.debug("Packets sent: {}".format(len(acks)))
            logging.debug("Sending rate: {}".format(rate))
            logging.debug("Loss rate: {}".format(loss_rate))
            logging.debug("RTT: {}".format(rtt_now))
            logging.debug("Throughput: {}".format(throughput * MAX_DATA_SIZE))
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
                                if not infodict['retransmitted']:
                                    self.update_rtt(received - infodict['timestamp'])
                                sacked_infodict = infodict

                        if decoded_msg['flags'] & IS_ACK:
                            ack_num = decoded_msg['acknum']
                            new_ack = True

                            while len(self.packets_in_flight) > 0:
                                if self.packets_in_flight[0][1]['ACKed']:
                                    heapq.heappop(self.packets_in_flight)
                                elif self._end_seqnum(self.packets_in_flight[0][1]['packet']) < ack_num:
                                    infodict = heapq.heappop(self.packets_in_flight)[1]

                                    infodict['ACKed'] = True
                                    del self.in_flight_dict[infodict['packet']['seqnum']]

                                    # Do stuff with monitoring
                                    self.on_ack(infodict, received)
                                else:
                                    new_ack = False
                                    break

                            if new_ack:
                                self.time_to_retransmit = t.time() + self.rto

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

                    if len(self.packets_in_flight) > 0:
                        if t.time() > self.time_to_retransmit or \
                            (not self.packets_in_flight[0][1]['retransmitted'] and
                                self.packets_in_flight[0][1].has_key('MI') and
                                not np.isinf(self.packets_in_flight[0][1]['MI']['utility'])):
                            infodict = self.packets_in_flight[0][1]
                            infodict['retransmitted'] = True

                            infodict.pop('MI', None)      # Assume packet is lost if it was retransmitted.
                            infodict.pop('MI_idx', None)  # Will ignore during monitoring.

                            self.time_to_retransmit = np.inf
                            logging.debug('Retransmitting packet with sequence number {}'.format(
                                infodict['packet']['seqnum'])
                            )
                            logging.debug('Current RTO value: {}'.format(self.rto))
                    else:
                        self.time_to_retransmit = np.inf

                    # No packets to retransmit this time, send a new one if possible.
                    if infodict is None and len(self.packets_in_flight) < 1000:
                        data = self.read_data(MAX_DATA_SIZE)
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
                        self.on_send(infodict, self.time_since_transmit)
                        if np.isinf(self.time_to_retransmit):
                            self.time_to_retransmit = t.time() + self.rto
                        if infodict['retransmitted']:
                            self.rto *= 2.0

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
        # Allegro monitor handling and rate control
        if self.has_estimated_rtt and self.cur_MI is None:
            self.allegro_state = SLOW_START
        if self.allegro_state != WAITING_FIRST_SRTT:
            if self.cur_MI is None:
                self.start_new_MI()
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                logging.debug("Started a new monitor interval.")
                logging.debug("MI #{}".format(self.cur_MI['idx']))
                logging.debug("Sending rate: {}".format(self.cur_MI['rate']))
                logging.debug("Current RTT estimate: {}s.".format(self.cur_MI['rtt']))
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
            elif t.time() - self.cur_MI["start"] > 2.5 * self.cur_MI["rtt"]:
                if self.allegro_state == SLOW_START:
                    if len(self.past_MI_utilities) >= 2 and self.past_MI_utilities[-1] < self.past_MI_utilities[-2]:
                        self.cur_rate = self.past_MI_rates[-2]
                        self.base_rate = self.cur_rate
                        self.allegro_state = DECISION_STATE
                        self.rct_idx = 0
                        self.allegro_cur_start_MI = self.cur_MI['idx'] + 1
                        logging.debug("Exiting out of slow start phase.")
                    else:
                        self.cur_rate *= 2.0
                elif self.allegro_state == DECISION_STATE:
                    if self.rct_idx == 0:
                        # Initialize randomized control trial
                        phase1 = random.randint(0, 1) * 2 - 1
                        phase2 = random.randint(0, 1) * 2 - 1
                        self.rct_ordering = (phase1, phase1 * -1, phase2, phase2 * -1)

                    self.cur_rate = (1.0 + self.rct_ordering[self.rct_idx] * self.experiment_granularity) * self.base_rate
                    self.rct_idx += 1

                    if self.rct_idx == 4:
                        self.allegro_state = WAITING_RESULTS
                elif self.allegro_state == WAITING_RESULTS:
                    self.cur_rate = self.base_rate  # Set back to base rate since the experiment is over.
                    if len(self.past_MI_utilities) > self.allegro_cur_start_MI + 5:   # Once we get results
                        idx = self.allegro_cur_start_MI

                        # Phase 1 result
                        if self.past_MI_utilities[idx + 1] > self.past_MI_utilities[idx + 2]:
                            phase1_winner = self.rct_ordering[0]
                        else:
                            phase1_winner = self.rct_ordering[1]

                        # Phase 2 result
                        if self.past_MI_utilities[idx + 3] > self.past_MI_utilities[idx + 4]:
                            phase2_winner = self.rct_ordering[2]
                        else:
                            phase2_winner = self.rct_ordering[3]

                        logging.debug("Phase 1 winner is: {} Phase 2 winner is: {}".format(phase1_winner, phase2_winner))
                        logging.debug('RCT Ordering was: {}'.format(self.rct_ordering))
                        if phase1_winner == phase2_winner:
                            # Unanimous. Choose this rate and move on to rate adjusting state.
                            logging.debug("Decided on direction {}.".format(phase1_winner))
                            self.decided_direction = phase1_winner
                            self.speed_to_increase = 1
                            self.base_rate = (1.0 + self.decided_direction * self.experiment_granularity) * self.base_rate
                            self.cur_rate = self.base_rate
                            self.experiment_granularity = self.eps_delta
                            self.rct_idx = 0
                            self.allegro_state = RATE_ADJUSTING_STATE
                            self.allegro_cur_start_MI = self.cur_MI['idx'] + 1
                        else:
                            logging.debug("Ambiguous result. Retrying decision state.")
                            # Try a higher granularity and retry decision state.
                            self.experiment_granularity += self.eps_delta
                            self.experiment_granularity = min(self.experiment_granularity, self.max_granularity)
                            self.rct_idx = 0
                            self.allegro_state = DECISION_STATE
                            self.allegro_cur_start_MI = self.cur_MI['idx'] + 1
                elif self.allegro_state == RATE_ADJUSTING_STATE:
                    # Try increasing. Then check if we should revert to a previous rate.
                    logging.debug("In Rate Adjusting State. Will try to change base rate by {}".format(self.speed_to_increase * self.decided_direction * self.experiment_granularity))
                    self.base_rate = (1.0 + self.speed_to_increase * self.decided_direction * self.experiment_granularity) * self.base_rate
                    self.cur_rate = self.base_rate
                    self.speed_to_increase += 1

                    # If we have information available from past MIs, use it.
                    if len(self.past_MI_utilities) > self.allegro_cur_start_MI + 3:
                        idx = self.allegro_cur_start_MI
                        for i in range(idx+1, len(self.past_MI_utilities)-1):
                            if self.past_MI_utilities[i] > self.past_MI_utilities[i+1]:
                                # Utility has decreased. Revert the rate and move back to decision making.
                                logging.debug('Utility has decreased from index {} to {}. Will revert to decision state.'.format(i, i+1))
                                self.base_rate = self.past_MI_rates[i]
                                self.cur_rate = self.base_rate
                                self.rct_idx = 0
                                self.allegro_cur_start_MI = self.cur_MI['idx'] + 1
                                self.allegro_state = DECISION_STATE

                self.start_new_MI()
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                logging.debug("Started a new monitor interval.")
                logging.debug("MI #{}".format(self.cur_MI['idx']))
                logging.debug("Sending rate: {}".format(self.cur_MI['rate']))
                logging.debug("Current RTT estimate: {}s.".format(self.cur_MI['rtt']))
                logging.debug("Current RTO: {}s.".format(self.cur_MI['rtt']))

                if self.allegro_state != SLOW_START:
                    logging.debug("")
                    logging.debug("MI is part of experiment group that started with MI #{}.".format(self.allegro_cur_start_MI))
                    logging.debug("Current state: {}".format(ALLEGRO_STATE[self.allegro_state]))
                    logging.debug("Experiment group base rate: {}".format(self.base_rate))
                logging.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

    def on_send(self, infodict, time_sent):
        if self.allegro_state != WAITING_FIRST_SRTT and not infodict['retransmitted']:
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

    def read_garbage_data(num_chars):
        return ' ' * num_chars

    client = Client((options.ip, options.port), read_garbage_data)
    client.run()
    lipsum.close()
