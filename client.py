from __future__ import division

import socket
import json
import optparse
import select
import random
import time as t
import heapq

import logging
logging.basicConfig(format='[%(asctime)s.%(msecs)03d] CLIENT - %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S', filename='network.log', level=logging.WARNING)


IS_SYN =   0x1
IS_FIN =   0x2
IS_ACK =   0x4
IS_RESET = 0x8

MAX_PACKET_SIZE = 1500
MAX_DATA_SIZE = 1400
MAX_RETRANSMIT  = 10
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


class TCPClient:
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
        self.server_ack = -1  # The sequence number the server has ACKd
        self.retransmit_count = 0  # Number of times has our last message been retransmitted.

        # Send buffer
        # Contains {timestamp, packet, retransmitted, ACKed}. Retransmits will happen upon timeout.
        # We can also use this to set estimated RTT, when retransmitted = False.
        self.packets_in_flight = []  # Priority by sequence number
        self.retransmit_queue = []  # Priority by retransmission timer

        self.estimated_rtt = 1.0  # in seconds
        self.deviation = 1.0
        self.time_since_transmit = 0.0
        self.retransmission_timeout = self.estimated_rtt * 2

        self.num_bytes_since_measuring = 0
        self.num_packets_since_measuring = 0
        self.last_time_measured = t.time()
        self.measure_intervals = 1.0

        # Congestion control
        self.congestion_window = 1
        self.slow_start = True
        self.duplicate_acks = 0
        self.time_of_congestion_event = 0.0

    def syn_packet(self):
        return create_packet(self.our_seq, 0, "", 0, IS_SYN)

    def ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK)

    def compute_measurements(self):
        logging.warn('Estimated RTT is: {}'.format(self.estimated_rtt))
        logging.warn('Number of packets in flight: {}'.format(len(self.packets_in_flight)))
        logging.warn('Retransmission queue size: {}'.format(len(self.retransmit_queue)))
        logging.warn('Retransmission timeout: {}'.format(self.retransmission_timeout))
        logging.warn('Congestion Window: {}'.format(self.congestion_window))
        logging.warn('SLOW START: {}'.format(self.slow_start))
        self.last_time_measured = t.time()
        self.num_bytes_since_measuring = 0
        self.num_packets_since_measuring = 0

    def send_packet(self, packet):
        data = json.dumps(packet).encode()
        logging.info('Sending packet with data size: {}'.format(len(data)))
        logging.info('Max data size: {}'.format(MAX_DATA_SIZE))
        try:
            self.sock.sendto(
                data,
                self.server
            )
        except:
            logging.error('Unable to send packet.')

    def update_rto(self, sample, reset=False):
        pass

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
                                ack_received = True
                                self.ack_seq = decoded_msg['seqnum']
                                self.retransmit_count = 0
                                logging.info('Received SYN-ACK for Client Seq {} Server Seq {}'.format(self.our_seq, self.ack_seq))

                                self.send_packet(self.ack_packet())
                                self.state = ESTABLISHED
                                self.time_of_congestion_event = t.time()
                                logging.warning('Connection established for Client.')


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
                current_time = t.time()
                if current_time > self.last_time_measured + self.measure_intervals:
                    self.compute_measurements()

                # Check if we have any new ACKs
                try:
                    msg, addr = self.sock.recvfrom(1600)
                    received = t.time()
                    decoded_msg = json.loads(msg.decode())

                    if decoded_msg['flags'] & IS_ACK:
                        ack_num = decoded_msg['acknum']
                        if self.server_ack == ack_num:
                            self.duplicate_acks += 1

                            if self.duplicate_acks == 3:
                                # Fast retransmit
                                pass
                        else:
                            self.duplicate_acks = 0

                        self.server_ack = max(self.server_ack, ack_num)

                        while len(self.packets_in_flight) > 0:
                            packet_least_seqnum = self.packets_in_flight[0][1]['packet']
                            if packet_least_seqnum['seqnum'] + len(packet_least_seqnum['data']) - 1 < ack_num:
                                acked_infodict = heapq.heappop(self.packets_in_flight)[1]

                                if self.slow_start:
                                    self.congestion_window += 1.0
                                    logging.warn('Congestion window updated to {}'.format(self.congestion_window))
                                    logging.warn('Retransmit timeout {}'.format(self.retransmission_timeout))
                                else:
                                    self.congestion_window += 1.0 / self.congestion_window

                                if acked_infodict['retransmitted'] == 0:
                                    # Use to update Estimated RTT.

                                    # Jacobson/Karels Algorithm
                                    sample_rtt = received - acked_infodict['timestamp']
                                    difference = sample_rtt - self.estimated_rtt
                                    self.estimated_rtt = self.estimated_rtt + difference * 0.125
                                    self.deviation = self.deviation + 0.125 * (abs(difference) - self.deviation)
                                    self.retransmission_timeout = 2 * self.estimated_rtt + 4 * self.deviation

                                    # Karn Algorithm
                                    #self.estimated_rtt = self.estimated_rtt * ALPHA + sample_rtt * (1.0 - ALPHA)
                                    #self.retransmission_timeout = self.estimated_rtt * 2
                                    #logging.warn('Updated RTT {}'.format(self.estimated_rtt))
                                del acked_infodict['packet']        # Free memory associated with packet, since already ACKed
                                acked_infodict['ACKed'] = True
                            else:
                                break
                except:
                    # No packet
                    pass

                # Check if we should transmit any new packets.
                if self.congestion_window > len(self.packets_in_flight):
                    # TODO this is where congestion control goes.
                    data = self.read_data(MAX_DATA_SIZE)
                    if len(data) == 0:
                        if len(self.packets_in_flight) == 0:
                            logging.info('Finished transmitting all data.')
                            self.state = CLOSED
                            return
                    else:
                        packet = create_packet(self.our_seq + 1, self.ack_seq + 1, data, 0, IS_ACK)

                        self.our_seq += len(data)
                        self.send_packet(packet)
                        self.time_since_transmit = t.time()
                        infodict = {
                            'timestamp': self.time_since_transmit,
                            'packet': packet,
                            'retransmitted': 0,
                            'ACKed': False
                        }
                        heapq.heappush(self.packets_in_flight, (packet['seqnum'], infodict))
                        heapq.heappush(self.retransmit_queue, (infodict['timestamp'] + self.retransmission_timeout, infodict))

                # Check if we should retransmit any existing packets.
                current_time = t.time()
                while len(self.retransmit_queue) > 0:
                    if current_time > self.retransmit_queue[0][0]:
                        if self.retransmit_queue[0][1]['ACKed']:
                            heapq.heappop(self.retransmit_queue)
                            #logging.warn('popping from retransmit queue')
                        else:
                            to_retransmit_infodict = heapq.heappop(self.retransmit_queue)[1]
                            self.send_packet(to_retransmit_infodict['packet'])

                            self.congestion_window = max(self.congestion_window / 2.0, 1)
                            self.slow_start = False

                            to_retransmit_infodict['retransmitted'] += 1

                            # Exponential backoff retransmission time when there is a retransmission.
                            retransmission_time = t.time() + self.retransmission_timeout
                            self.retransmission_timeout *= 2
                            self.retransmission_timeout = min(self.retransmission_timeout, 5)  # Don't suddenly blow up.

                            heapq.heappush(self.retransmit_queue, (retransmission_time, to_retransmit_infodict))
                            logging.warn('Retransmitting packet with seqnum {}'.format(to_retransmit_infodict['packet']['seqnum']))
                    else:
                        break
            else:
                logging.error('Incorrect TCP State.')
                self.state = CLOSED
                return


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

    client = TCPClient((options.ip, options.port), read_garbage_data)
    client.run()
    lipsum.close()
