import socket
import json
import optparse
import select
import random
import time as t
import heapq

import logging
logging.basicConfig(format='[%(asctime)s.%(msecs)03d] CLIENT - %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S', filename='network.log', level=logging.DEBUG)


IS_SYN =   0x1
IS_FIN =   0x2
IS_ACK =   0x4
IS_RESET = 0x8

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

        # Send buffer
        # Contains {timestamp, packet, retransmitted, ACKed}. Retransmits will happen upon timeout.
        # We can also use this to set estimated RTT, when retransmitted = False.
        self.packets_in_flight = []
        self.retransmit_queue = []
        self.estimated_rtt = 1.0  # in seconds
        self.time_since_transmit = 0.0

    def syn_packet(self):
        return create_packet(self.our_seq, 0, "", 0, IS_SYN)

    def ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK)

    def send_packet(self, packet):
        self.sock.sendto(
            json.dumps(packet).encode(),
            self.server
        )


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
                                logging.info('Connection established for Client.')


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
                try:
                    msg, addr = self.sock.recvfrom(1600)
                    received = t.time()
                    decoded_msg = json.loads(msg.decode())

                    if decoded_msg['flags'] & IS_ACK:
                        ack_num = decoded_msg['acknum']

                        while len(self.packets_in_flight) > 0:
                            packet_least_seqnum = self.packets_in_flight[0][1]['packet']
                            if packet_least_seqnum['seqnum'] + len(packet_least_seqnum['data']) - 1 < ack_num:
                                acked_infodict = heapq.heappop(self.packets_in_flight)[1]
                                if not acked_infodict['retransmitted']:
                                    # Use to update Estimated RTT.
                                    sample_rtt = received - acked_infodict['timestamp']
                                    self.estimated_rtt = self.estimated_rtt * ALPHA + sample_rtt * (1.0 - ALPHA)
                                    logging.debug('Updated RTT {}'.format(self.estimated_rtt))
                                del acked_infodict['packet']        # Free memory associated with packet, since already ACKed
                                acked_infodict['ACKed'] = True
                            else:
                                break
                except:
                    # No packet
                    pass

                # Check if we should transmit any new packets.
                if t.time() - self.time_since_transmit > 0.1:
                    # TODO this is where congestion control goes.
                    data = self.read_data(MAX_PACKET_SIZE)
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
                            'retransmitted': False,
                            'ACKed': False
                        }
                        heapq.heappush(self.packets_in_flight, (packet['seqnum'], infodict))
                        heapq.heappush(self.retransmit_queue, (infodict['timestamp'], infodict))

                # Check if we should retransmit any existing packets.
                while len(self.retransmit_queue) > 0:
                    if t.time() > self.retransmit_queue[0][0]:
                        if self.retransmit_queue[0][1]['ACKed']:
                            heapq.heappop(self.retransmit_queue)
                        else:
                            to_retransmit_infodict = heapq.heappop(self.retransmit_queue)[1]
                            self.send_packet(to_retransmit_infodict['packet'])
                            to_retransmit_infodict['retransmitted'] = True
                            heapq.heappush(self.retransmit_queue, (t.time() + 2 * self.estimated_rtt, to_retransmit_infodict))
                            logging.debug('Retransmitting packet with data {}'.format(to_retransmit_infodict['packet']['data']))
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

    client = Client((options.ip, options.port), read_data)
    client.run()
    lipsum.close()
