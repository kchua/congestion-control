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

        self.algo = 'RENO'

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

        # Keeping track of RTT and RTO according to RFC6298
        self.srtt = -1.0  # in seconds
        self.rttvar = -1.0
        self.rto = 1.0

        self.num_bytes_since_measuring = 0
        self.num_packets_since_measuring = 0
        self.last_time_measured = t.time()
        self.measure_intervals = 1.0

        # Congestion control
        self.cwnd = 3  # Initial window set to 3 packets.
        self.ssthresh = 1000  # Initially set to arbitrarily high.
        self.rwnd = 1000  # Manually set to not overwhelm receiver.
        self.slow_start = True
        self.duplicate_acks = 0
        self.time_of_transmit = 0.0

    def syn_packet(self):
        return create_packet(self.our_seq, 0, "", 0, IS_SYN)

    def ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK)

    def compute_measurements(self):
        logging.warn('Estimated RTT is: {}'.format(self.srtt))
        logging.warn('Number of packets in flight: {}'.format(len(self.packets_in_flight)))
        logging.warn('Retransmission timeout: {}'.format(self.rto))
        logging.warn('Congestion Window: {}'.format(self.cwnd))
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
                            logging.warn('Received packet from unidentified server.')
                            continue

                        if (decoded_msg['flags'] & IS_SYN) and (decoded_msg['flags'] & IS_ACK):
                            if decoded_msg['acknum'] == self.our_seq + 1:
                                ack_received = True
                                self.ack_seq = decoded_msg['seqnum']
                                self.retransmit_count = 0
                                logging.info('Received SYN-ACK for Client Seq {} Server Seq {}'.format(self.our_seq, self.ack_seq))

                                self.send_packet(self.ack_packet())
                                self.state = ESTABLISHED
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
                    received_time = t.time()
                    decoded_msg = json.loads(msg.decode())

                    if decoded_msg['flags'] & IS_ACK:
                        ack_num = decoded_msg['acknum']
                        if self.server_ack == ack_num:
                            self.duplicate_acks += 1

                            if self.duplicate_acks == 3:
                                if self.algo == 'RENO':
                                    # Reno has fast recovery
                                    self.retransmit_packet(True, current_time)
                                else:
                                    self.retransmit_packet(False, current_time)
                        else:
                            self.duplicate_acks = 0

                        self.server_ack = max(self.server_ack, ack_num)

                        while len(self.packets_in_flight) > 0:
                            packet_least_seqnum = self.packets_in_flight[0][1]['packet']
                            if packet_least_seqnum['seqnum'] + len(packet_least_seqnum['data']) - 1 < ack_num:
                                acked_infodict = heapq.heappop(self.packets_in_flight)[1]

                                if self.slow_start:
                                    self.cwnd += 1.0
                                    logging.info('Congestion window updated to {}'.format(self.cwnd))
                                    logging.info('Retransmit timeout {}'.format(self.rto))
                                else:
                                    self.cwnd += 1.0 / self.cwnd

                                if self.cwnd > self.ssthresh:
                                    self.slow_start = False

                                if acked_infodict['retransmitted'] == 0:
                                    # Since this packet is not a retransmitted packet, use it to update srtt.

                                    # Jacobson/Karels Algorithm
                                    # Also Karn Algorithm - Do not calculate from retransmitted packets.
                                    sample_rtt = received_time - acked_infodict['timestamp']
                                    if self.srtt < 0:
                                        # First time setting srtt
                                        self.srtt   = sample_rtt
                                        self.rttvar = sample_rtt / 2.0
                                        self.rto    = self.srtt + max(0.010, 4 * self.rttvar)
                                    else:
                                        alpha = 0.125
                                        beta  = 0.25

                                        self.rttvar = (1 - beta) * self.rttvar + beta * abs(self.srtt - sample_rtt)
                                        self.srtt   = (1 - alpha) * self.srtt + alpha * sample_rtt
                                        self.rto    = self.srtt + max(0.010, 4 * self.rttvar)
                                    self.rto = max(self.rto, 1)  # Always round up RTO.
                                    self.rto = min(self.rto, 60)  # Maximum value 60 seconds.
                                acked_infodict['ACKed'] = True
                            else:
                                break
                except socket.error:
                    # No packet
                    pass

                # Check if we should transmit any new packets.
                if min(self.rwnd, self.cwnd) > len(self.packets_in_flight):
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
                        self.time_of_transmit = t.time()
                        infodict = {
                            'timestamp': self.time_of_transmit,
                            'packet': packet,
                            'retransmitted': 0,
                            'ACKed': False
                        }
                        heapq.heappush(self.packets_in_flight, (packet['seqnum'], infodict))

                # Check if we should retransmit any existing packets.
                current_time = t.time()
                if current_time > self.rto + self.time_of_transmit:
                    self.retransmit_packet(False, current_time)

            else:
                logging.error('Incorrect TCP State.')
                self.state = CLOSED
                return

    def retransmit_packet(self, fast_recovery, current_time):
        assert not self.packets_in_flight[0][1]['ACKed']
        to_retransmit = self.packets_in_flight[0][1]

        self.send_packet(to_retransmit['packet'])
        logging.warn('Client RETRANSMITTING packet.')
        self.time_of_transmit = current_time

        if to_retransmit['retransmitted'] == 0:
            # RFC5681 Equation (4)
            self.ssthresh = max(len(self.packets_in_flight), 2)

        # Restart from small congestion window, update ssthresh, begin slow start.
        if fast_recovery:
            self.slow_start = False
            self.cwnd = self.ssthresh
        else:
            self.slow_start = True
            self.cwnd = 1
        to_retransmit['retransmitted'] += 1


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
