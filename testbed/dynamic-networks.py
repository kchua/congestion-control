import os
import random
import time
import optparse
import errno

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.cli import CLI
from mininet.link import TCLink


def create_topology():
    topo = Topo()
    topo.addSwitch('s1')
    topo.addHost('h1')
    topo.addHost('h2')
    topo.addLink(
        'h1', 's1',
        bw=500,
    )
    topo.addLink(
        's1', 'h2',
        **generate_random_tc_params()
    )

    return Mininet(topo=topo, link=TCLink, waitConnected=True)



def generate_random_tc_params():
    return {
        "bw": random.randint(10, 100),
        "delay": '{}ms'.format(int(random.uniform(5, 50) * 10)/10.0)
    }


def main(ntrials):
    lg.setLogLevel('info')

    algos = ["vivace", "allegro", "cubic", "client"]

    try:
        os.makedirs("results/dynamic-topology")
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise

    for trial in range(ntrials):
        for algo in algos:
            net = create_topology()
            net.start()
            dynamic_link = net.get('h2').connectionsTo(net.get('s1'))[0]

            h1 = net.get('h1')
            server_log = open("server.log", "w")
            p1 = h1.popen(
                "python ../server.py -i {} -l results/dynamic-topology/{}-server-{}.json".format(
                    h1.IP(),
                    algo if algo != "client" else "reno",
                    trial
                ),
                stdout=server_log, stderr=server_log
            )

            h2 = net.get('h2')
            client_log = open("client.log", "w")
            p2 = h2.popen(
                "python ../{}.py -i {} -l results/dynamic-topology/{}-client-{}.json".format(
                    algo,
                    h1.IP(),
                    algo if algo != "client" else "reno",
                    trial
                ),
                stdout=client_log, stderr=client_log
            )

            start_time = time.time()

            while time.time() < start_time + (5 * 60):
                time.sleep(5)
                new_params = generate_random_tc_params()
                dynamic_link[0].config(**new_params)
                dynamic_link[1].config(**new_params)

            p1.terminate()
            p2.terminate()
            net.stop()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-n', dest='ntrials', help='Number of trials per algorithm', type='int')
    (options, args) = parser.parse_args()

    main(options.ntrials)
