__author__ = 'elio'

from ecnspider import MergedRecord
import itertools
import ecnspider
import multiprocessing.managers
import multiprocessing.connection
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
    def __init__(self, id, pipe):
        self.id = id
        self.pipe = pipe

        self.ordered = 0
        self.finished = 0

class Master:

    def __init__(self):
        logger = logging.getLogger('master')
        logger.setLevel(logging.DEBUG)
        logger.debug("Started")

        parser = argparse.ArgumentParser(description='Ecnspider2 master. Manages ecnspider slaves.')
        parser.add_argument('slaves', metavar='ID:HOST:PORT', nargs='+',
                       help='id:host:port of slave to manage, where id is an arbitrary string to distinguish them in the csv file.')
        parser.add_argument('--file', '-f', metavar='FILENAME', help='Write results into CSV-File.', dest='outfile', required=True, type=argparse.FileType('w'))
        parser.add_argument('--count', '-N', dest='count', metavar='N', type=int, default=10, help='Count of addresses to test.')
        args = parser.parse_args()

        self.lock = threading.Lock()

        self.count = args.count

        self.running = False

        self.outfile = args.outfile

        class QueueManager(multiprocessing.managers.BaseManager): pass
        QueueManager.register('pipe')

        self.slaves = []
        for slave in args.slaves:
            id, ip, port = slave.split(':')
            addr = (ip, int(port))

            logger.debug('connecting to {}'.format(addr))
            m = QueueManager(address=addr, authkey=b'whatever')
            m.connect()
            self.slaves.append(Slave(id, m.pipe()))

    def jobcreator(self):
        logger = logging.getLogger('master')
        logger.info('jobcreator started')
        dht = torrent.TorrentDhtSpider(unique=True)
        dht.start()
        jobs_sent = 0
        while self.running and jobs_sent < self.count:
            # package jobs togheter
            jobs = [ecnspider.Job(ip_address(addr[0]), addr[0], addr[1]) for addr, _ in zip(dht, range(200))]

            # send to each slave
            for slave in self.slaves:
                slave.pipe.send(jobs)

                with self.lock:
                    slave.ordered += len(jobs)

            jobs_sent += len(jobs)
            logger.debug("Send ({} of {})".format(jobs_sent, self.count))

        # mark end of jobs
        for slave in self.slaves:
            slave.pipe.send(None)

        logger.info('jobcreator finished')

    def jobreceiver(self):
        logger = logging.getLogger('master')
        logger.info('jobreceiver started')

        while self.running and not all([slave.finished >= 2*self.count for slave in self.slaves]):
            for slave in self.slaves:
                if not slave.pipe.poll():
                    continue

                results = slave.pipe.recv()
                for result in results:
                    with self.lock:
                        slave.finished += 1
                    self.outfile.write("{s},{r.ip},{r.port},{r.rport},{r.ecnstate},{r.connstate},{r.fif},{r.fsf},{r.fuf},{r.fir},{r.fsr},{r.fur}\n".format(s=slave.id, r=result))

            print("Received", [slave.finished for slave in self.slaves], "of", 2*self.count)

            time.sleep(1)
        logger.info("jobreceiver finished")
        self.running = False

    def run(self):
        self.running = True

        jc = threading.Thread(target=self.jobcreator, name='jobcreator')
        jc.start()

        jr = threading.Thread(target=self.jobreceiver, name='ĵobreceiver')
        jr.start()

        while self.running:
            time.sleep(1)
        logger = logging.getLogger('master')
        logger.info('finished')

def main():
    handler = ecnspider.log_to_console(logging.DEBUG)
    ipfix.ie.use_iana_default()
    ipfix.ie.use_specfile("qof.iespec")

    logging.getLogger('master').addHandler(handler)

    master = Master()

    master.run()

if __name__ == "__main__":
    main()