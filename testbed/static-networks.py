import optparse
import time
import os
import errno

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.cli import CLI
from mininet.link import TCLink


def create_topology(topo_type, topo_var):
    topo = Topo()
    topo.addSwitch('s1')
    topo.addHost('h1')
    topo.addHost('h2')

    if topo_type == "random_loss_resilience":
        topo.addLink(
            'h1', 's1',
            bw=100,
            delay='7.5ms',
            loss=0,
        )
        topo.addLink(
            's1', 'h2',
            bw=100,
            delay='7.5ms',
            max_queue_size=50,
            loss=topo_var,
        )
    elif topo_type == "satellite_link":
        topo.addLink(
            'h1', 's1',
            bw=24,
            delay='200ms',
            max_queue_size=topo_var,
            loss=0,
        )
        topo.addLink(
            's1', 'h2',
            bw=24,
            delay='200ms',
            loss=1
        )
    elif topo_type == "bufferbloat":
        topo.addLink(
            'h1', 's1',
            bw=100,
            delay='7.5ms',
            max_queue_size=topo_var,
            loss=0,
        )
        topo.addLink(
            's1', 'h2',
            bw=100,
            delay='7.5ms',
            loss=0
        )

    net = Mininet(topo=topo, link=TCLink, waitConnected=True)
    return net


def main(topology, ntrials):
    lg.setLogLevel('info')

    algos = ["vivace", "allegro", "cubic", "client"]
    if topology == "random_loss_resilience":
        variants = [1, 2, 3, 4, 5]
    elif topology == "satellite_link":
        variants = [25, 50, 75, 100, 125]
    elif topology == "bufferbloat":
        variants = [5, 10, 15, 20, 25]
    else:
        raise ValueError("Invalid topology.")

    for variant in variants:
        for trial in range(ntrials):
            for algo in algos:
                # Create topology.
                net = create_topology(topology, variant)
                net.start()

                try:
                    os.makedirs("results/{}".format(topology))
                except OSError as err:
                    if err.errno != errno.EEXIST:
                        raise

                h1 = net.get('h1')
                server_log = open("server.log", "w")
                p1 = h1.popen(
                    "python ../server.py -i {} -l results/{}/{}-{}-server-{}.json".format(
                        h1.IP(),
                        topology,
                        str(variant),
                        algo if algo != "client" else "reno",
                        trial
                    ),
                    stdout=server_log, stderr=server_log
                )

                h2 = net.get('h2')
                client_log = open("client.log", "w")
                p2 = h2.popen(
                    "python ../{}.py -i {} -l results/{}/{}-{}-client-{}.json".format(
                        algo,
                        h1.IP(),
                        topology,
                        str(variant),
                        algo if algo != "client" else "reno",
                        trial
                    ),
                    stdout=client_log, stderr=client_log
                )

                time.sleep(3 * 60)

                p1.terminate()
                p2.terminate()
                net.stop()


if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option('-t', dest='topo', help='Topology type to test ["random_loss_resilience", "satellite_link", "bufferbloat"]')
    parser.add_option('-n', dest='ntrials', help='Number of trials per algorithm and setting', type='int')
    (options, args) = parser.parse_args()

    main(options.topo, options.ntrials)
