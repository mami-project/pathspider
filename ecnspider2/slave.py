__author__ = 'elio'

import ecnspider
import multiprocessing.managers
import queue
import qofspider
import ipfix
import logging
import sys
import argparse
import threading

def main():
    qofspider.log_to_console(logging.DEBUG)
    ipfix.ie.use_iana_default()
    ipfix.ie.use_specfile("qof.iespec")

    parser = argparse.ArgumentParser(description='Ecnspider2 slave. Executes ecnspider jobs.')
    parser.add_argument('--interface-uri', '-i', metavar='INTERFACE', dest='interface_uri', required=True, help='Libtrace input source URI. (e.g. int:eth0)')
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
    QueueManager.register('run', callable=ecn.run)
    QueueManager.register('stop', callable=ecn.stop)

    #jobadder = threading.Thread(target=lambda:ecn.add_job(jobs.get(True)), daemon=True)
    #jobadder.start()
    def adder():
        while True:
            ecn.add_job(jobs.get(True))

    jobadder = threading.Thread(target=adder, daemon=True)
    jobadder.start()


    m = QueueManager(address=('127.0.0.1', 49999), authkey=b'whatever')
    s = m.get_server()
    s.serve_forever()



if __name__ == "__main__":
    main()
