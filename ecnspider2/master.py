__author__ = 'elio'

from ecnspider import MergedRecord
import ecnspider
import multiprocessing.managers
from ipaddress import ip_address
import queue
import qofspider
import ipfix
import logging
import argparse
import torrent
import threading
import collections
import time

class Slave:
    def __init__(self, jobs, results, stop):
        self.jobs = jobs
        self.results = results
        self.stop = stop

        self.ordered = 0
        self.finished = 0

class Master:

    def __init__(self):
        logger = logging.getLogger('master')
        logger.setLevel(logging.DEBUG)
        logger.debug("Started")

        parser = argparse.ArgumentParser(description='Ecnspider2 master. Manages ecnspider slaves.')
        parser.add_argument('slaves', metavar='HOST:PORT', nargs='+',
                       help='host:port of slave to manage.')
        parser.add_argument('--count', '-N', dest='count', metavar='N', type=int, default=1000, help='Count of addresses to test.')
        args = parser.parse_args()

        self.lock = threading.Lock()

        self.count = args.count

        self.running = False

        class QueueManager(multiprocessing.managers.BaseManager): pass
        QueueManager.register('get_results_queue')
        QueueManager.register('get_jobs_queue')
        QueueManager.register('stop')

        self.slaves = []
        for slave in args.slaves:
            ip, port = slave.split(':')
            addr = (ip, int(port))

            logger.debug('connecting to {}'.format(addr))
            m = QueueManager(address=addr, authkey=b'whatever')
            m.connect()
            self.slaves.append(Slave(m.get_jobs_queue(), m.get_results_queue(), m.stop))

    def jobcreator(self):
        logger = logging.getLogger('master')
        logger.info('jobcreator started')
        dht = torrent.TorrentDhtSpider()
        ips = set()
        for addr in dht:
            if not self.running:
                return

            if len(ips) >= self.count:
                break

            if addr[0] not in ips:
                ips.add(addr[0])

                logger.debug("Send job: {}".format(addr))

                for slave in self.slaves:
                    slave.jobs.put(ecnspider.Job(ip_address(addr[0]), addr[0], addr[1]))

                    with self.lock:
                        slave.ordered += 1

    def jobreceiver(self):
        logger = logging.getLogger('master')
        logger.info('jobreceiver started')

        while self.running or all([slave.finished >= self.count for slave in self.slaves]):
            for idx, slave in enumerate(self.slaves):
                try:
                    while True:
                        result = slave.results.get_nowait()
                        with self.lock:
                            slave.finished += 1
                        logger.debug("Got result from {}: {}".format(idx, result))
                except queue.Empty:
                    continue

            time.sleep(0.1)

    def run(self):
        self.running = True

        jc = threading.Thread(target=self.jobcreator, name='jobcreator')
        jc.start()

        jr = threading.Thread(target=self.jobreceiver, name='ĵobreceiver')
        jr.start()

        while self.running:
            time.sleep(1)

def main():
    handler = qofspider.log_to_console(logging.DEBUG)
    ipfix.ie.use_iana_default()
    ipfix.ie.use_specfile("qof.iespec")

    logger = logging.getLogger('master')
    logger.addHandler(handler)

    master = Master()

    master.run()

if __name__ == "__main__":
    main()