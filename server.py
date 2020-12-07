from __future__ import division

import random
import json
import socket
import optparse
import select
import logging
import heapq

import time as t
logging.basicConfig(format='[%(asctime)s.%(msecs)03d] SERVER - %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S', filename='network.log', level=logging.WARNING)


IS_SYN         = 0x1
IS_FIN         = 0x2
IS_ACK         = 0x4
IS_RESET       = 0x8
SACK_PERMITTED = 0x10
IS_SACK        = 0x20

MAX_PACKET_SIZE = 1500
MAX_RETRANSMIT  = 10
HEADER_OVERHEAD = 28


def create_packet(seqnum, acknum, data, rwnd, flags, sack_left=None, sack_right=None):
    packet = {
        'seqnum': seqnum,
        'acknum': acknum,
        'data':   data,
        'rwnd':   rwnd,
        'flags':  flags,
    }
    if sack_left is not None and sack_right is not None:
        packet['sack_left'] = sack_left
        packet['sack_right'] = sack_right
    return packet


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


class Server:
    def __init__(self, address, process_message, logfile=None):
        """
        Creates a server.
        """
        self.receiver = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(address)
        self.poller = select.poll()
        self.poller.register(self.sock, ALL_FLAGS)
        self.process_message = process_message
        self.logfile = logfile

        self.recv_buffer_size = 1000000

        # TCP State that will be updated throughout the run.
        self.state = LISTEN  # Start off as passive listener.
        self.our_seq = random.randrange(1024)  # The current sequence number on our side.
        self.ack_seq = -1  # The sequence number we have acknowledged.
        self.retransmit_count = 0  # Number of times has our last message been retransmitted.
        self.send_sacks = False

        # Received data, possibly out of order.
        self.packet_buffer = []

        self.num_bytes_since_measuring = 0
        self.num_packets_since_measuring = 0
        self.last_time_measured = t.time()
        self.measure_intervals = 1.0

        self.total_packets_acked = 0
        self.time_start = 0

    def send_packet(self, packet):
        data = json.dumps(packet).encode()
        logging.info('Sending packet with data size: {}'.format(len(data)))
        try:
            self.sock.sendto(
                data,
                self.receiver
            )
        except:
            logging.error('Unable to send packet.')

    def process_data_packet(self, p):
        newly_ACKed_segments = 0
        start = t.time()

        end_seq = self._end_seqnum(p)
        p['end_seqnum'] = end_seq
        del p['data']

        if Server._end_seqnum(p) >= self.ack_seq + 1:
            heapq.heappush(self.packet_buffer, (p['seqnum'], p))

            while len(self.packet_buffer) > 0:
                if Server._end_seqnum(self.packet_buffer[0][1]) < self.ack_seq + 1:
                    heapq.heappop(self.packet_buffer)   # Duplicate packet
                elif self.packet_buffer[0][1]['seqnum'] <= self.ack_seq + 1:
                    packet = heapq.heappop(self.packet_buffer)[1]
                    difference = self.ack_seq + 1 - packet['seqnum']
                    self.process_message(self._end_seqnum(packet) - packet['seqnum'] + 1)
                    # self.process_message(packet['data'])
                    self.ack_seq = Server._end_seqnum(packet)
                    newly_ACKed_segments += 1
                else:
                    break
        end = t.time()
        self.total_packets_acked += newly_ACKed_segments
        if newly_ACKed_segments > 1:
            logging.warning('Total newly ACKed segments: {} segments'.format(newly_ACKed_segments))
            logging.warning('ACKing required {}s'.format(end - start))
            logging.warning('Total queue length: {} segments'.format(len(self.packet_buffer)))

    def syn_packet(self):
        return create_packet(self.our_seq, 0, "", 0, IS_SYN)

    def ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK)

    def sack_packet(self, sack_left, sack_right):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK | IS_SACK, sack_left=sack_left, sack_right=sack_right)

    def syn_ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK | IS_SYN)

    def compute_measurements(self):
        throughput = self.num_bytes_since_measuring / self.measure_intervals
        logging.warning('Total throughput in last {} seconds: {} Bytes / Second'.format(self.measure_intervals, throughput))
        logging.warning('Total packets in last {} seconds: {}'.format(self.measure_intervals, self.num_packets_since_measuring))
        self.last_time_measured = t.time()
        self.num_bytes_since_measuring = 0
        self.num_packets_since_measuring = 0

    def run(self):
        """
        Runs the server.
        """
        while True:
            if self.state == CLOSED:
                pass
            elif self.state == LISTEN:
                msg, addr = self.sock.recvfrom(1600)
                decoded_msg = json.loads(msg.decode())
                if decoded_msg['flags'] & IS_SYN:
                    self.receiver = addr
                    self.ack_seq = decoded_msg['seqnum']
                    if decoded_msg['flags'] & SACK_PERMITTED:
                        self.send_sacks = True
                        logging.info("Selective ACKs are enabled.")
                    logging.info("Made first contact with %s. Sending response..." % str(addr))

                    self.sock.setblocking(0)
                    self.poller.modify(self.sock, READ_ERR_FLAGS)

                    # Send the SYN-ACK packet, go into SYN_RCVD mode.
                    self.send_packet(self.syn_ack_packet())
                    self.state = SYN_RCVD

            elif self.state == SYN_SENT:
                pass
            elif self.state == SYN_RCVD:
                events = self.poller.poll(1000)  # Poll for one second

                ack_received = False
                # We have received something. Parse it.
                for fd, flag in events:
                    assert self.sock.fileno() == fd

                    if flag & ERR_FLAGS:
                        logging.error('Error flags set.')
                    elif flag & READ_FLAGS:
                        msg, addr = self.sock.recvfrom(1600)
                        decoded_msg = json.loads(msg.decode())

                        if addr != self.receiver:
                            logging.warn('Received packet from unidentified client.')
                            continue

                        if (decoded_msg['flags'] & IS_ACK):
                            if decoded_msg['acknum'] == self.our_seq + 1:
                                ack_received = True
                                self.retransmit_count = 0
                                logging.info('Received ACK for Server Seq {}'.format(self.our_seq))

                                self.state = ESTABLISHED
                                self.time_start = t.time()
                                logging.info('Connection established for Server.')

                                # Check if there is data in the ACK.
                                if len(decoded_msg['data']) > 0:
                                    self.process_data_packet(decoded_msg)
                                    if self.send_sacks:
                                        self.send_packet(self.sack_packet(
                                            decoded_msg['seqnum'], decoded_msg['end_seqnum'] + 1
                                        ))
                                    else:
                                        self.send_packet(self.ack_packet())

                # If events is empty, retransmit or fail.
                if not events or not ack_received:
                    self.retransmit_count += 1

                    if self.retransmit_count > MAX_RETRANSMIT:
                        logging.error("Exceeded {} attempts. Giving up.".format(MAX_RETRANSMIT))
                        self.state = CLOSED
                        return

                    # Do the retransmission.
                    self.send_packet(self.syn_ack_packet())
                    logging.warn("Retrying SYN-ACK packet.")

            elif self.state == ESTABLISHED:
                current_time = t.time()
                if current_time > self.last_time_measured + self.measure_intervals:
                    self.compute_measurements()
                    if self.logfile is not None:
                        with open(self.logfile, 'w') as log:
                            json.dump({
                                'time_since_start': current_time - self.time_start,
                                'total_packets': self.total_packets_acked
                            }, log)

                events = self.poller.poll(1000)  # Poll for one second

                packet_received = False
                # We have received something. Parse it.
                for fd, flag in events:
                    assert self.sock.fileno() == fd

                    if flag & ERR_FLAGS:
                        logging.error('Error flags set.')
                        self.state = CLOSED
                        self.retransmit_count = 0
                        return
                    if flag & READ_FLAGS:
                        msg, addr = self.sock.recvfrom(1600)
                        self.num_bytes_since_measuring += len(msg)
                        self.num_bytes_since_measuring += HEADER_OVERHEAD
                        self.num_packets_since_measuring += 1
                        decoded_msg = json.loads(msg.decode())

                        if addr != self.receiver:
                            logging.warn('Received packet from unidentified client.')
                            continue

                        self.retransmit_count = 0
                        if len(decoded_msg['data']) > 0:
                            #logging.warning('Server seen seqnum: {}'.format(decoded_msg['seqnum']))
                            self.process_data_packet(decoded_msg)
                            #logging.warning('Server has ACKd: {}'.format(self.ack_seq))
                            if self.send_sacks:
                                self.send_packet(self.sack_packet(
                                    decoded_msg['seqnum'], decoded_msg['end_seqnum'] + 1
                                ))
                            else:
                                self.send_packet(self.ack_packet())
                            packet_received = True


                # If events is empty, retransmit or fail.
                if not events or not packet_received:
                    self.retransmit_count += 1

                    if self.retransmit_count > MAX_RETRANSMIT:
                        logging.error("Exceeded {} attempts. Giving up.".format(MAX_RETRANSMIT))
                        self.state = CLOSED
                        return

                    # Do the retransmission.
                    self.send_packet(self.ack_packet())
                    logging.warn("Sending heartbeat ACK packet.")
            else:
                logging.error('Incorrect TCP State.')
                self.state = CLOSED
                return

    @staticmethod
    def _end_seqnum(packet):
        if packet.has_key('end_seqnum'):
            return packet['end_seqnum']
        return packet['seqnum'] + len(packet['data']) - 1

def test_process_data_packet(server):
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    server.ack_seq = 0
    for i in range(100):
        rand_ind = random.randrange(23)
        server.process_data_packet(create_packet(rand_ind + 1, 0, alpha[rand_ind:(rand_ind+4)], 0, 0))


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-i', dest='ip', default='')
    parser.add_option('-p', dest='port', type='int', default=12345)
    parser.add_option('-l', dest='logfile', default=None)
    (options, args) = parser.parse_args()

    lipsum = open('lipsum_server.txt', 'w')
    def process_message(message):
        logging.info('Message received: {}'.format(message))
        lipsum.write(message)

    def process_garbage_message(message):
        logging.info('Message received with size {}'.format(len(message)))

    def process_garbage_message_v2(num_bytes):
        logging.info('Message received with size {}'.format(num_bytes))

    server = Server((options.ip, options.port), process_garbage_message_v2, options.logfile)
    server.run()
    lipsum.close()
