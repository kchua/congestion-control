#!/usr/bin/python
import time

from mininet.topo import Topo, SingleSwitchTopo
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.cli import CLI
from mininet.link import TCLink


def main():
    lg.setLogLevel('info')

    # Build the topology we want to play with:
    #
    #             +-----------------------+
    #             |     10Mbit/s link     |
    #             |     5ms delay         |
    #             |     10% packet loss   |
    #             |                       |
    #             +-----------+-----------+
    #                         |
    #                         |
    #                         |
    #                         |
    # +-------------+         v        +-------------+
    # |             |                  |             |
    # | host 1 (h1) +------------------+ host 2 (h2) |
    # |             |                  |             |
    # +-------------+                  +-------------+
    #
    topo = Topo()

    switch = topo.addSwitch( 's1' )
    topo.addHost('h1')
    topo.addHost('h2')
    topo.addLink('h1','s1', bw=10, delay='100ms', loss=0)
    topo.addLink('h2','s1', bw=10, delay='100ms', loss=0)

    # The TCLink is needed for use to set the bandwidth, delay and loss
    # constraints on the link
    #
    # waitConnected
    net = Mininet(topo=topo,
                  link=TCLink,
                  waitConnected=True)
    net.start()

    h1 = net.get('h1')
    server_log = open("server.log", "w")
    p1 = h1.popen('python server.py -i %s' % h1.IP(), stdout=server_log, stderr=server_log)

    h2 = net.get('h2')
    client_log = open("client.log", "w")
    p2 = h2.popen('python allegro.py -i %s' % h1.IP(), stdout=client_log, stderr=client_log)

    #time.sleep(10)
    #link = h2.connectionsTo(net.get('s1'))[0]
    #link[0].config(delay='50ms')
    #link[1].config(delay='50ms')
    #time.sleep(20)

    CLI(net)
    p1.terminate()
    p2.terminate()
    net.stop()


if __name__ == '__main__':
    main()
