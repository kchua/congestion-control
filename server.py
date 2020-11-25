import random
import json
import socket
import optparse
import select
import logging
logging.basicConfig(format='[%(asctime)s.%(msecs)03d] SERVER - %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S', filename='network.log', level=logging.INFO)


IS_SYN =   0x1
IS_FIN =   0x2
IS_ACK =   0x4
IS_RESET = 0x8

MAX_PACKET_SIZE = 1500
MAX_RETRANSMIT  = 50


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


class Server:
    def __init__(self, address, process_message):
        """
        Creates a server.
        """
        self.receiver = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(address)
        self.poller = select.poll()
        self.poller.register(self.sock, ALL_FLAGS)
        self.process_message = process_message

        self.recv_buffer_size = 1000000

        # TCP State that will be updated throughout the run.
        self.state = LISTEN  # Start off as passive listener.
        self.our_seq = random.randrange(1024)  # The current sequence number on our side.
        self.ack_seq = -1  # The sequence number we have acknowledged.
        self.retransmit_count = 0  # Number of times has our last message been retransmitted.

        # Received data, possibly out of order.
        self.packet_buffer = []

    def send_packet(self, packet):
        self.sock.sendto(
            json.dumps(packet).encode(),
            self.receiver
        )

    def process_data_packet(self, p):
        self.packet_buffer.append(p)

        # Check if any packets in the buffer can be delivered.
        # To do so, sort by sequence number and see if they can be delivered in order.
        self.packet_buffer.sort(key=lambda x: x['seqnum'])
        new_packet_buffer = []
        for packet in self.packet_buffer:
            if packet['seqnum'] + len(packet['data']) - 1 >= self.ack_seq + 1:
                # Check if packet should be buffered or processed immediately.
                if packet['seqnum'] <= self.ack_seq + 1:
                    difference = self.ack_seq + 1 - packet['seqnum']
                    self.process_message(packet['data'][difference:])
                    self.ack_seq += len(packet['data'][difference:])
                else:
                    new_packet_buffer.append(packet)

        self.packet_buffer = new_packet_buffer

    def syn_packet(self):
        return create_packet(self.our_seq, 0, "", 0, IS_SYN)

    def ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK)

    def syn_ack_packet(self):
        return create_packet(self.our_seq, self.ack_seq + 1, "", 0, IS_ACK | IS_SYN)

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
                        self.state = CLOSED
                        self.retransmit_count = 0
                        return
                    if flag & READ_FLAGS:
                        msg, addr = self.sock.recvfrom(1600)
                        decoded_msg = json.loads(msg.decode())

                        if addr != self.receiver:
                            logging.warn('Received packet from unidentified client.')
                            continue

                        if (decoded_msg['flags'] & IS_ACK):
                            if decoded_msg['acknum'] == self.our_seq + 1:
                                ack_received = True
                                self.ack_seq = decoded_msg['seqnum']
                                self.retransmit_count = 0
                                logging.info('Received ACK for Server Seq {}'.format(self.our_seq))

                                self.state = ESTABLISHED
                                logging.info('Connection established for Server.')

                                # Check if there is data in the ACK.
                                if len(decoded_msg['data']) > 0:
                                    self.process_data_packet(decoded_msg)
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
                        decoded_msg = json.loads(msg.decode())

                        if addr != self.receiver:
                            logging.warn('Received packet from unidentified client.')
                            continue

                        self.retransmit_count = 0
                        if len(decoded_msg['data']) > 0:
                            self.process_data_packet(decoded_msg)
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
    (options, args) = parser.parse_args()

    lipsum = open('lipsum_server.txt', 'w')
    def process_message(message):
        logging.info('Message received: {}'.format(message))
        lipsum.write(message)
        lipsum.flush()

    server = Server((options.ip, options.port), process_message)
    server.run()
    lipsum.close()
