import socket
import json
import optparse
import select
import random
from helper import print_with_time

READ_FLAGS = select.POLLIN | select.POLLPRI
WRITE_FLAGS = select.POLLOUT
ERR_FLAGS = select.POLLERR | select.POLLHUP | select.POLLNVAL
READ_ERR_FLAGS = READ_FLAGS | ERR_FLAGS
ALL_FLAGS = READ_FLAGS | WRITE_FLAGS | ERR_FLAGS


class Client:
    def __init__(self, server):
        """
        Creates a client which will attempt to connect to
        the server determined by the (ip, port) tuple in the
        server argument.
        """
        self.server = server
        self.is_connected = False
        self.seq_start = None
        self.server_seq_start = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.poller = select.poll()
        self.poller.register(self.sock, ALL_FLAGS)

    def perform_handshake(self):
        self.seq_start = random.randrange(1024)
        self.sock.setblocking(0)
        self.poller.modify(self.sock, READ_ERR_FLAGS)

        print_with_time("Attempting handshake.")

        num_attempts = 0
        while not self.is_connected:
            self.sock.sendto(
                json.dumps({
                    "SYN": self.seq_start
                }).encode(),
                self.server
            )

            print_with_time("Sent first message, waiting for response.")

            events = self.poller.poll(1000)  # Poll for one second

            if not events:
                num_attempts += 1
                if num_attempts > 10:
                    return

            for fd, flag in events:
                assert self.sock.fileno() == fd

                if flag & ERR_FLAGS:
                    return
                if flag & READ_FLAGS:
                    msg, addr = self.sock.recvfrom(1600)
                    decoded_msg = json.loads(msg.decode())
                    if addr == self.server and decoded_msg["ACK"] == self.seq_start + 1:
                        self.is_connected = True
                        self.server_seq_start = decoded_msg["SYN"]

        print_with_time(
            "Confirmed handshake from server. Sending acknowledgment."
        )
        self.sock.sendto(
            json.dumps({
                "ACK": self.server_seq_start + 1
            }).encode(),
            self.server
        )

        print_with_time("Successfully connected to server. Goodbye!")

    def run(self):
        pass

parser = optparse.OptionParser()
parser.add_option('-i', dest='ip', default='127.0.0.1')
parser.add_option('-p', dest='port', type='int', default=12345)
(options, args) = parser.parse_args()

client = Client((options.ip, options.port))
client.perform_handshake()

# s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.sendto(options.msg, (options.ip, options.port))
# s.sendto(options.msg, (options.ip, options.port))
