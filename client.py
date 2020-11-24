import socket
import json
import optparse
import select
import random

import logging
logging.basicConfig(format='[%(asctime)s.%(msecs)03d] CLIENT - %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S', filename='network.log', level=logging.INFO)


IS_SYN =   0x1
IS_FIN =   0x2
IS_ACK =   0x4
IS_RESET = 0x8

MAX_PACKET_SIZE = 1500
MAX_RETRANSMIT  = 10


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
    def __init__(self, server):
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

        # TCP State that will be updated throughout the run.
        self.state = CLOSED
        self.our_seq = random.randrange(1024)  # The current sequence number on our side.
        self.ack_seq = -1  # The sequence number we have acknowledged.
        self.retransmit_count = 0  # Number of times has our last message been retransmitted.

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
                pass
            else:
                logging.error('Incorrect TCP State.')
                self.state = CLOSED
                return

    def transmit_message(self, message):
        if not self.is_connected:
            logging.error('Cannot transmit packet without connection.')
            return False

        packet = json.dumps({
            'SYN': self.seq_start + 1,
            'DATA': message,
        }).encode()

        num_attempts = 0
        while True:
            self.sock.sendto(
                packet,
                self.server
            )

            # Wait for an acknowledgement
            events = self.poller.poll(1000)
            if not events:
                num_attempts += 1
                logging.warn('Packet {} dropped!'.format(self.seq_start + 1))
                logging.warn('Retransmitting packet {}'.format(self.seq_start + 1))

                if num_attempts > 10:
                    logging.error("Exceeded 10 attempts. Giving up.")
                    return False

            for fd, flag in events:
                assert self.sock.fileno() == fd

                if flag & ERR_FLAGS:
                    return
                if flag & READ_FLAGS:
                    msg, addr = self.sock.recvfrom(1600)
                    decoded_msg = json.loads(msg.decode())
                    if addr == self.server and decoded_msg["ACK"] == self.seq_start + 1:
                        logging.info('Packet {} acknowledged.'.format(self.seq_start + 1))
                        self.seq_start += 1
                        return True

        logging.error('Should not get here...')
        return False

    #def run(self):
    #    for i in range(100):
    #        result = self.transmit_message('hello there')
    #        if not result:
    #            logging.error('Error transmitting.')
    #            return

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-i', dest='ip', default='127.0.0.1')
    parser.add_option('-p', dest='port', type='int', default=12345)
    (options, args) = parser.parse_args()

    client = Client((options.ip, options.port))
    #client.connect()
    client.run()

# s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.sendto(options.msg, (options.ip, options.port))
# s.sendto(options.msg, (options.ip, options.port))
