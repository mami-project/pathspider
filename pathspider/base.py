"""
Basic framework for Pathspider: coordinate active measurements on large target
lists with both system-level network stack state (sysctls, iptables rules, etc)
as well as information derived from flow-level passive observation of traffic at
the sender.

.. moduleauthor:: Brian Trammell <brian@trammell.ch>

"""

import sys
import time
import logging
import collections
import threading
import multiprocessing as mp
import queue
from datetime import datetime

from pathspider.network import ipv4_address
from pathspider.network import ipv6_address
from pathspider.network import ipv4_address_public
from pathspider.network import ipv6_address_public
from pathspider.network import ipv4_asn
from pathspider.network import ipv6_asn

__version__ = "2.1.0.dev0"

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2
CONN_SKIPPED = 3
CONN_DISCARD = 4

PORT_FAILED = 0
PORT_FAILED_AGAIN = -1

QUEUE_SIZE = 1000
QUEUE_SLEEP = 0.5

SHUTDOWN_SENTINEL = "SHUTDOWN_SENTINEL"
NO_FLOW = None

class Spider:
    """
    A spider consists of a configurator (which alternates between two system
    configurations), a large number of workers (for performing some network
    action for each configuration), an Observer which derives information from
    passively observed traffic, and a thread that merges results from the
    workers with flow records from the collector.

    """

    name = "spider"
    chains = [] # Disable the observer by default

    def __init__(self, worker_count, libtrace_uri, args, server_mode):
        """
        The initialisation of a pathspider plugin.

        :param worker_count: The number of workers to use.
        :type worker_count: int
        :param libtrace_uri: The URI to pass to the Observer to describe the
                             interface on which packets should be captured.
        :type libtrace_uri: str
        :param server_mode: Whether the spider should operate in server mode
        :type server_mode: bool

        It is expected that this function will be overloaded by plugins, though
        the plugin should always make a call to the __init__() function of the
        abstract Spider class as this initialises all of the base functionality:

        .. code-block:: python

         super().__init__(worker_count=worker_count,
                          libtrace_uri=libtrace_uri,
                          args=args,
                          server_mode=server_mode)

        This can be used to initialise any variables which may be required in
        the object.
        """

        self.worker_count = worker_count
        self.args = args
        self.libtrace_uri = libtrace_uri
        self.server_mode = server_mode

        self.__initialize_queues()
        self.__set_interface_addresses()

        self.lock = threading.Lock()
        self.exception = None

        self.__logger = logging.getLogger('pathspider')

    def __initialize_queues(self):
        # TODO: These could be initialized closer to where they are used?
        self.jobqueue = queue.Queue(QUEUE_SIZE)
        self.resqueue = queue.Queue(QUEUE_SIZE)
        self.flowqueue = mp.Queue(QUEUE_SIZE)
        self.observer_shutdown_queue = mp.Queue(QUEUE_SIZE)
        self.jobtab = {}
        self.comparetab = {}
        self.restab = {}
        self.flowtab = {}
        self.flowreap = collections.deque()
        self.flowreap_size = min(self.worker_count * 100, 10000)
        self.outqueue = queue.Queue(QUEUE_SIZE)

    def __set_interface_addresses(self):
        if self.libtrace_uri.startswith('int'):
            self.source = (ipv4_address(self.libtrace_uri[4:]),
                           ipv6_address(self.libtrace_uri[4:]))
            self.source_public = (ipv4_address_public(self.libtrace_uri[4:]),
                                  ipv6_address_public(self.libtrace_uri[4:]))
            self.source_asn = (ipv4_asn(self.libtrace_uri[4:]),
                               ipv6_asn(self.libtrace_uri[4:]))
        else:
            self.source = ("127.0.0.1", "::1")

    def _get_test_count(self):
        if hasattr(self, 'packets'):
            return self.packets # pylint: disable=no-member
        if hasattr(self, 'configurations'):
            return len(self.configurations) # pylint: disable=no-member
        if hasattr(self, 'connections'):
            return len(self.connections) # pylint: disable=no-member

    def configurator(self):
        raise NotImplementedError("Cannot instantiate an abstract Spider")

    def worker(self, worker_number):
        raise NotImplementedError("Cannot instantiate an abstract Spider")

    def _connect_wrapper(self, job, config, connect=None):
        start = str(datetime.utcnow())
        if connect is None:
            conn = self.connect(job, config) # pylint: disable=no-member
        else:
            if not hasattr(connect, '__self__'):
                connect = connect.__get__(self)
            conn = connect(job, config)
        conn['spdr_start'] = start
        return conn

    def create_observer(self):
        """
        Create a flow observer.

        This function is called by the base Spider logic to get an instance
        of :class:`pathspider.observer.Observer` configured with the function
        chains that are requried by the plugin.
        """

        self.__logger.info("Creating observer")
        if len(self.chains) > 0:
            from pathspider.observer import Observer
            return Observer(self.libtrace_uri,
                            chains=self.chains) # pylint: disable=no-member
        else:
            from pathspider.observer import DummyObserver
            return DummyObserver()

    def _key(self, obj):
        if self.server_mode:
            objkey = (obj['sip'], obj['sp'])
        else:
            objkey = (obj['dip'], obj['sp'])
        return objkey

    def _merge_flows(self):
        try:
            flow = self.flowqueue.get_nowait()
        except queue.Empty:
            time.sleep(QUEUE_SLEEP)
            return True
        else:
            if flow == SHUTDOWN_SENTINEL:
                self.__logger.debug("stopping flow merging on sentinel")
                return False

            flowkey = self._key(flow)
            self.__logger.debug("got a flow (" + repr(flowkey) + ")")

            if flowkey in self.restab:
                self.__logger.debug("merging flow")
                self.merge(flow, self.restab[flowkey])
                del self.restab[flowkey]
            elif flowkey in self.flowtab:
                self.__logger.debug("won't merge duplicate flow")
            else:
                # Create a new flow
                self.flowtab[flowkey] = flow

                # And reap the oldest, if the reap queue is full
                self.flowreap.append(flowkey)
                if len(self.flowreap) > self.flowreap_size:
                    try:
                        del self.flowtab[self.flowreap.popleft()]
                    except KeyError:
                        pass
            return True

    def _merge_results(self):
        try:
            res = self.resqueue.get_nowait()
        except queue.Empty:
            time.sleep(QUEUE_SLEEP)
            self.__logger.debug("result queue is empty")
            return True
        else:
            if res == SHUTDOWN_SENTINEL:
                self.__logger.debug("stopping result merging on sentinel")
                return False
            if 'spdr_state' in res.keys() and res['spdr_state'] == CONN_SKIPPED:
                # handle skipped results
                return True

            reskey = self._key(res)
            self.__logger.debug("got a result (" + repr(reskey) + ")")

            if reskey in self.restab and res['sp'] == PORT_FAILED:
                # both connections failed, but need to be distinguished
                reskey = (reskey[0], PORT_FAILED_AGAIN)

            if reskey in self.flowtab:
                self.__logger.debug("merging result")
                self.merge(self.flowtab[reskey], res)
                del self.flowtab[reskey]
            elif reskey in self.restab:
                self.__logger.debug("won't merge duplicate result")
            else:
                self.restab[reskey] = res

            self.resqueue.task_done()
            return True

    def merger(self):
        """
        Thread to merge results from the workers and the observer.
        """

        if len(self.chains) == 0:
            self.__logger.warning("Merger is not expecting flows from the Observer")
            # Immediately merge with NO_FLOW when there's no chains, as there's
            # going to also be no observer and so no flows.
            while self.running:
                try:
                    res = self.resqueue.get_nowait()
                except queue.Empty:
                    time.sleep(QUEUE_SLEEP)
                    self.__logger.debug("result queue is empty")
                    continue
                if res == SHUTDOWN_SENTINEL:
                    break
                if not ('spdr_state' in res.keys() and res['spdr_state'] == CONN_SKIPPED):
                    self.merge(NO_FLOW, res)
        else:
            merging_flows = True
            merging_results = True

            while self.running and (merging_results or merging_flows):

                if merging_flows and self.flowqueue.qsize() >= self.resqueue.qsize():
                    merging_flows = self._merge_flows()

                elif merging_results:
                    merging_results = self._merge_results()

        # One more pass during shutdown, to clean up any leftovers
        for res_item in self.restab.items():
            res = res_item[1]
            self.merge(NO_FLOW, res)

    def merge(self, flow, res):
        """
        Merge a job record with a flow record.

        :param flow: The flow record.
        :type flow: dict
        :param res: The job record.
        :type res: dict
        :return: tuple -- Final record for job.

        In order to create a final record for reporting on a job, the final job
        record must be merged with the flow record. This function should
        be implemented by any plugin to provide the logic for this merge as
        the keys used in these records cannot be known by PATHspider in advance.

        This method is not implemented in the abstract
        :class:`pathspider.base.Spider` class and must be implemented by any
        plugin.
        """

        if flow == NO_FLOW:
            flow = {'observed': False}
        else:
            flow['observed'] = True

        for key in res.keys():
            if key in flow.keys():
                if res[key] == flow[key]:
                    continue
                else:
                    self.__logger.warning("Dropping flow due to mismatch with "
                                          "observations on key %s", key)
                    return
            flow[key] = res[key]

        # Remove private keys - we need to make a copy of the keys as we
        #                       modify the dict during the iteration
        for key in [x for x in flow.keys()]:
            if key.startswith("_"):
                flow.pop(key)

        self.__logger.debug("Result: " + str(flow))

        if flow['jobId'] not in self.comparetab:
            self.comparetab[flow['jobId']] = []
        self.comparetab[flow['jobId']].append(flow)

        if len(self.comparetab[flow['jobId']]) == self._config_count: # pylint: disable=no-member
            flows = self.comparetab.pop(flow['jobId'])
            flows.sort(key=lambda x: x['config'])
            start = min([flow['spdr_start'] for flow in flows])
            stop = max([flow['spdr_stop'] for flow in flows])
            job = self.jobtab.pop(flow['jobId'])
            job['flow_results'] = flows
            job['time'] = {'from': start, 'to': stop}
            job['missed_flows'] = 0
            for flow in flows:
                if not flow['observed']:
                    job['missed_flows'] = job['missed_flows'] + 1
            job['conditions'] = self.combine_flows(flows)
            if job['conditions'] is not None:
                if "pathspider.not_observed" in job['conditions']:
                    self.__logger.debug("At least one flow was not observed and so conditions could not be fully generated (if at all)")
                if job['missed_flows'] > 0:
                    job['conditions'].append("pathspider.missed_flows:" + str(job['missed_flows']))
            else:
                job.pop('conditions')
            self.outqueue.put(job)

    def combine_flows(self, flows):
        return []

    def exception_wrapper(self, target, *args, **kwargs):
        try:
            target(*args, **kwargs)
        except: # pylint: disable=W0702
            self.__logger = logging.getLogger('pathspider')
            self.__logger.exception("exception occurred. terminating.")
            if self.exception is None:
                self.exception = sys.exc_info()[1]
            self.terminate()

    def _finalise_conns(self, job, jobId, conns):
        # Pass results on for merge
        config = 0
        for conn in conns:
            conn['spdr_stop'] = str(datetime.utcnow())
            conn['config'] = config
            if self.server_mode:
                conn['sip'] = job['sip']
            else:
                conn['dip'] = job['dip']
            conn['jobId'] = jobId
            self.resqueue.put(conn)
            config += 1

    def start(self):
        """
        This function starts a PATHspider plugin by:

         * Setting the running flag
         * Create and start an observer
         * Start the merger thread
         * Start the configurator thread
         * Start the worker threads

        The number of worker threads to start was given when activating the
        plugin.
        """

        self.__logger.info("starting pathspider")

        self.worker_threads = []
        self.active_worker_count = 0
        self.active_worker_lock = threading.Lock()

        with self.lock:
            # set the running flag
            self.running = True
            
            self.stopping = False

            # create an observer and start its process
            self.observer = self.create_observer()
            self.observer_process = mp.Process(
                args=(self.observer.run_flow_enqueuer,
                      self.flowqueue,
                      self.observer_shutdown_queue),
                target=self.exception_wrapper,
                name='observer',
                daemon=True)
            self.observer_process.start()
            self.__logger.debug("observer forked")

            # now start up ecnspider, backwards
            self.merger_thread = threading.Thread(
                args=(self.merger,),
                target=self.exception_wrapper,
                name="merger",
                daemon=True)
            self.merger_thread.start()
            self.__logger.debug("merger up")

            self.configurator_thread = threading.Thread(
                args=(self.configurator,),
                target=self.exception_wrapper,
                name="configurator",
                daemon=True)
            self.configurator_thread.start()
            self.__logger.debug("configurator up")
            self.worker_threads = []
            with self.active_worker_lock:
                self.active_worker_count = self.worker_count
            for i in range(self.worker_count):
                worker_thread = threading.Thread(
                    args=(self.worker, i),
                    target=self.exception_wrapper,
                    name='worker_{}'.format(i),
                    daemon=True)
                self.worker_threads.append(worker_thread)
                worker_thread.start()
            self.__logger.debug("workers up")

    def shutdown(self):
        """
        Shut down PathSpider in an orderly fashion,
        ensuring that all queued jobs complete,
        and all available results are merged.

        """

        self.__logger.info("beginning shutdown")

        with self.lock:
            # Set stopping flag
            self.stopping = True

            # Put a bunch of shutdown signals in the job queue
            for _ in range(self.worker_count * 2):
                self.jobqueue.put(SHUTDOWN_SENTINEL)

            # Wait for worker threads to shut down
            for worker in self.worker_threads:
                if threading.current_thread() != worker:
                    self.__logger.debug("joining worker: " + repr(worker))
                    worker.join()
            self.__logger.debug("all workers joined")

            # Tell observer to shut down
            self.observer_shutdown_queue.put(True)
            self.observer_process.join()
            self.__logger.debug("observer shutdown")

            # Tell merger to shut down
            self.resqueue.put(SHUTDOWN_SENTINEL)
            self.merger_thread.join()
            self.__logger.debug("merger shutdown")

            # Wait for merged results to be written
            self.outqueue.join()
            self.__logger.debug("all results retrieved")

            # Propagate shutdown sentinel and tell threads to stop
            self.outqueue.put(SHUTDOWN_SENTINEL)

            # Tell threads we've stopped
            self.running = False

            # Join configurator
            # if threading.current_thread() != self.configurator_thread:
            #     self.configurator_thread.join()

            self.stopping = False

        self.__logger.info("shutdown complete")

    def terminate(self):
        """
        Shut down PathSpider as quickly as possible,
        without any regard to completeness of results.

        """
        self.__logger.info("terminating pathspider")

        # tell threads to stop
        self.stopping = True
        self.running = False

        # terminate observer
        self.observer_shutdown_queue.put(True)

        # drain queues
        try:
            while True:
                self.jobqueue.task_done()
        except ValueError:
            pass

        try:
            while True:
                self.resqueue.task_done()
        except ValueError:
            pass

        try:
            while True:
                self.flowqueue.get_nowait()
        except queue.Empty:
            pass

        # Join remaining threads
        for worker in self.worker_threads:
            if threading.current_thread() != worker:
                self.__logger.debug("joining worker: " + repr(worker))
                worker.join()
        self.__logger.debug("all workers joined")

        if self.configurator_thread and \
                (threading.current_thread() != self.configurator_thread):
            self.configurator_thread.join()
            self.__logger.debug("configurator joined")

        if threading.current_thread() != self.merger_thread:
            self.merger_thread.join()
            self.__logger.debug("merger joined")

        self.observer_process.join()
        self.__logger.debug("observer joined")

        self.outqueue.put(SHUTDOWN_SENTINEL)
        self.__logger.info("termination complete")

    def add_job(self, job):
        """
        Adds a job to the job queue. Before inserting into the queue, the local
        IP addresses will be added to the job information. The path specifier
        will also be constructed using this information and any additional
        information that is available in the job record.

        If PATHspider is currently stopping, the job will not be added to the
        queue.
        """

        if self.stopping:
            return

        if not self.server_mode:
            if 'dip' in job.keys():
                sourceindex = 1 if ':' in job['dip'] else 0
                job['sip'] = self.source[sourceindex]
                job['path'] = [job['sip']]
                job['sip_public'] = self.source_public[sourceindex]
                if not ( job['sip'] == job['sip_public'] ):
                    job['path'].append(job['sip_public'])
                if self.source_asn[sourceindex] is not None:
                    job['sip_asn'] = self.source_asn[sourceindex]
                    job['path'].append("AS" + str(job['sip_asn']))
                if 'dip_asn' in job.keys(): # This may be generated by other tools
                    job['path'].append("AS" + job['dip_asn'])
                elif 'info' in job.keys(): # Hellfire does it this way
                    if 'ASN' in job['info'].keys():
                        job['path'].append("AS" + str(job['info']['ASN']))
                job['path'].append(job['dip'])

        self.jobqueue.put(job)

    def combine_connectivity(self, baseline, experimental=None, prefix=None):
        if prefix is None:
            prefix = self.name
        if experimental is None:
            if baseline:
                return prefix + ".connectivity.online"
            else:
                return prefix + ".connectivity.offline"
        if experimental:
            if baseline:
                return prefix + ".connectivity.works"
            else:
                return prefix + ".connectivity.transient"
        else:
            if baseline:
                return prefix + ".connectivity.broken"
            else:
                return prefix + ".connectivity.offline"


class PluggableSpider:
    @staticmethod
    def register_args(subparsers):
        raise NotImplementedError("Cannot register an abstract plugin")
