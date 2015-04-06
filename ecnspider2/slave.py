__author__ = 'elio'

import ecnspider
import multiprocessing.managers
import queue
import ipfix
import logging
import sys
import argparse
import threading
import time

def main():
    handler = ecnspider.log_to_console(logging.DEBUG)
    logger = logging.getLogger('slave')
    logger.addHandler(handler)

    ipfix.ie.use_iana_default()
    ipfix.ie.use_specfile("qof.iespec")

    parser = argparse.ArgumentParser(description='Ecnspider2 slave. Executes ecnspider jobs.')
    parser.add_argument('interface_uri', metavar='URI', help='Libtrace input source URI. (e.g. int:eth0)')
    args = parser.parse_args()

    if sys.platform == 'linux':
        configurator_hooks = ecnspider.EcnSpider2ConfigLinux()
    elif sys.platform == 'darwin':
        configurator_hooks = ecnspider.EcnSpider2ConfigDarwin()
    else:
        raise NotImplemented("Configurator for your system {} is not implemented.".format(sys.platform))

    results = queue.Queue()
    jobs = queue.Queue()

    ecn = ecnspider.EcnSpider2(result_sink=results.put,
        worker_count=50, conn_timeout=5,
        interface_uri=args.interface_uri,
        configurator_hooks=configurator_hooks,
        qof_port=54739)

    class QueueManager(multiprocessing.managers.BaseManager): pass
    QueueManager.register('get_results_queue', callable=lambda:results)
    QueueManager.register('get_jobs_queue', callable=lambda:jobs)

    m = QueueManager(address=('', 49999), authkey=b'whatever')

    def shutdown():
        logging.info("shutdown step 1 of 3: waiting for ecn to finish...")
        ecn.stop()
        logging.info("shutdown step 2 of 3: waiting for result queue to be empty...")
        while results.qsize() > 0:
            time.sleep(1)
        logging.info("shutdown step 3 of 3: teardown multiprocessing manager...")
        m.shutdown()
        logging.info("graceful shutdown complete.")

    #jobadder = threading.Thread(target=lambda:ecn.add_job(jobs.get(True)), daemon=True)
    #jobadder.start()
    def adder():
        while True:
            job = jobs.get(True)

            if job is None:
                logger.info('Received end of job notification. Initiate shutdown')
                shutdown()
                return

            ecn.add_job(job)

    jobadder = threading.Thread(target=adder, daemon=True)
    jobadder.start()

    ecn.run()

    s = m.get_server()
    s.serve_forever()

if __name__ == "__main__":
    main()
