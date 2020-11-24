#!/usr/bin/python

from mininet.topo import Topo, SingleSwitchTopo
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.cli import CLI

def main():
    lg.setLogLevel('info')

    net = Mininet(SingleSwitchTopo(k=2))
    net.start()

    h1 = net.get('h1')
    server_log = open("server-log.txt", "w")
    p1 = h1.popen('python Server.py -i %s' % h1.IP(), stdout=server_log, stderr=server_log)

    h2 = net.get('h2')
    client_log = open("client-log.txt", "w")
    h2.popen('python Client.py -i %s' % h1.IP(), stdout=client_log, stderr=client_log)

    CLI(net)
    p1.terminate()
    net.stop()

if __name__ == '__main__':
    main()
