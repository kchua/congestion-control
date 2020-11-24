import random
import json
import socket
import optparse
import select
from helper import print_with_time

READ_FLAGS = select.POLLIN | select.POLLPRI
WRITE_FLAGS = select.POLLOUT
ERR_FLAGS = select.POLLERR | select.POLLHUP | select.POLLNVAL
READ_ERR_FLAGS = READ_FLAGS | ERR_FLAGS
ALL_FLAGS = READ_FLAGS | WRITE_FLAGS | ERR_FLAGS


class Server:
    def __init__(self, address):
        """
        Creates a server.
        """
        self.address = address
        self.receiver = None
        self.is_connected = False
        self.seq_start = None
        self.client_seq_start = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(address)
        self.poller = select.poll()
        self.poller.register(self.sock, ALL_FLAGS)

    def wait_for_handshake(self):
        print_with_time("Waiting for handshake...")

        self.seq_start = random.randrange(1024)

        while True:
            msg, addr = self.sock.recvfrom(1600)
            decoded_msg = json.loads(msg.decode())
            if self.receiver is None:
                self.receiver = addr
                self.client_seq_start = decoded_msg["SYN"]
                break

        print_with_time("Made first contact with %s. Sending response..." % str(addr))

        self.sock.setblocking(0)
        self.poller.modify(self.sock, READ_ERR_FLAGS)

        num_timeouts = 0
        while not self.is_connected:
            self.sock.sendto(
                json.dumps({
                    "SYN": self.seq_start,
                    "ACK": self.client_seq_start + 1
                }).encode(),
                self.receiver
            )
            events = self.poller.poll(1000)

            print_with_time("Sent response. Waiting...")

            if not events:
                num_timeouts += 1
                if num_timeouts >= 10:
                    print_with_time("Handshake failed.")
                    return
                else:
                    print_with_time("No response received. Retrying.")
            else:
                for fd, flag in events:
                    assert self.sock.fileno() == fd
                    if flag & ERR_FLAGS:
                        return
                    if flag & READ_FLAGS:
                        msg, addr = self.sock.recvfrom(1600)
                        decoded_msg = json.loads(msg.decode())
                        if addr == self.receiver and decoded_msg.get("ACK") == self.seq_start + 1:
                            self.is_connected = True

        print_with_time("Connected successfully with host. Goodbye!")

    def run(self):
        """
        Runs the server.
        """
        pass


parser = optparse.OptionParser()
parser.add_option('-i', dest='ip', default='')
parser.add_option('-p', dest='port', type='int', default=12345)
(options, args) = parser.parse_args()

server = Server((options.ip, options.port))
server.wait_for_handshake()

# s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.bind((options.ip, options.port))
#
# f = open('foo.txt','w')
# while True:
#   data, addr = s.recvfrom(512)
#   f.write("%s: %s\n" % (addr, data))
#   f.flush()
