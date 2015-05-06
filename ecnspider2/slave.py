__author__ = 'elio'

import multiprocessing
import multiprocessing.managers
import queue
import ipfix
import logging
import sys
import argparse
import threading
import time
import os.path
from . import ecnspider

def main():
    handler = ecnspider.log_to_console(logging.DEBUG)
    logger = logging.getLogger('slave')
    logger.addHandler(handler)

    ipfix.ie.use_iana_default()
    ipfix.ie.use_5103_default()
    scriptdir = os.path.dirname(os.path.abspath(__file__))
    ipfix.ie.use_specfile(os.path.join(scriptdir, "qof.iespec"))

    parser = argparse.ArgumentParser(description='Ecnspider2 slave. Executes ecnspider jobs.')
    parser.add_argument('interface_uri', metavar='URI', help='Libtrace input source URI. (e.g. int:eth0)')
    args = parser.parse_args()

    pipe, pipe_remote = multiprocessing.Pipe(True)

    result_cache = queue.Queue()

    ecn = ecnspider.EcnSpider2(result_sink=result_cache.put,
        worker_count=200, conn_timeout=5,
        interface_uri=args.interface_uri,
        qof_port=54739)

    class QueueManager(multiprocessing.managers.BaseManager): pass
    QueueManager.register('pipe', callable=lambda:pipe_remote)

    m = QueueManager(address=('', 49999), authkey=b'whatever')

    def shutdown():
        logger.info("shutdown step 1 of 2: waiting for ecn to finish...")
        ecn.stop()
        logger.info("shutdown step 2 of 2: waiting for result queue to be empty...")
        while pipe_remote.poll():
            time.sleep(1)
        logger.info("bye.")
        exit()

    def result_sender():
        while True:
            to_send = []
            while result_cache.qsize() > 0:
                to_send.append(result_cache.get(False))

            if len(to_send) > 0:
                pipe.send(to_send)
            else:
                time.sleep(1)

    def job_receiver():
        while True:
            jobs = pipe.recv()

            if jobs is None:
                logger.info('Received end of job notification. Initiate shutdown')
                shutdown()
                return

            for job in jobs:
                ecn.add_job(job)

    job_receiver_thread = threading.Thread(target=job_receiver, daemon=True)
    job_receiver_thread.start()

    results_sender_thread = threading.Thread(target=result_sender, daemon=True)
    results_sender_thread.start()

    ecn.run()

    s = m.get_server()
    s.serve_forever()

if __name__ == "__main__":
    main()
