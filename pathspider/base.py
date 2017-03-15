"""
Basic framework for Pathspider: coordinate active measurements on large target
lists with both system-level network stack state (sysctls, iptables rules, etc)
as well as information derived from flow-level passive observation of traffic at
the sender.

.. moduleauthor:: Brian Trammell <brian@trammell.ch>

Derived and generalized from ECN Spider
(c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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

###
### Utility Classes
###

class SemaphoreN(threading.BoundedSemaphore):
    """
    An extension to the standard library's BoundedSemaphore that provides
    functions to handle n tokens at once.
    """
    def __init__(self, value):
        self._value = value
        super().__init__(self._value)
        self.empty()

    def __str__(self):
        return 'SemaphoreN with a maximum value of {}.'.format(self._value)

    def acquire_n(self, value=1, blocking=True, timeout=None):
        """
        Acquire ``value`` number of tokens at once.

        The parameters ``blocking`` and ``timeout`` have the same semantics as
        :class:`BoundedSemaphore`.

        :returns: The same value as the last call to `BoundedSemaphore`'s
        :meth:`acquire` if :meth:`acquire` were called ``value`` times instead
        of the call to this method.
        """
        ret = None
        for _ in range(value):
            ret = self.acquire(blocking=blocking, timeout=timeout)
        return ret

    def release_n(self, value=1):
        """
        Release ``value`` number of tokens at once.

        :returns: The same value as the last call to `BoundedSemaphore`'s
        :meth:`release` if :meth:`release` were called ``value`` times instead
        of the call to this method.
        """
        ret = None
        for _ in range(value):
            ret = self.release()
        return ret

    def empty(self):
        """
        Acquire all tokens of the semaphore.
        """
        while self.acquire(blocking=False):
            pass

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2
CONN_SKIPPED = 3

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

    def __init__(self, worker_count, libtrace_uri, args, server_mode):
        """
        The initialisation of a pathspider plugin.

        :param worker_count: The number of workers to use.
        :type worker_count: int
        :param libtrace_uri: The URI to pass to the Observer to describe the
                             interface on which packets should be captured.
        :type libtrace_uri: str

        It is expected that this function will be overloaded by plugins, though
        the plugin should always make a call to the __init__() function of the
        abstract Spider class as this initialises all of the base functionality:

        .. code-block:: python

         super().__init__(worker_count=worker_count,
                          libtrace_uri=libtrace_uri,
                          args=args)

        This can be used to initialise any variables which may be required in
        the object.
        """

        self.args = args

        self.running = False
        self.stopping = False
        self.terminating = False
        self.server_mode = server_mode

        self.worker_count = worker_count
        self.active_worker_count = 0
        self.active_worker_lock = threading.Lock()

        self.libtrace_uri = libtrace_uri

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

        self.observer = None

        self.worker_threads = []
        self.configurator_thread = None
        self.merger_thread = None

        self.observer_process = None

        self.lock = threading.Lock()
        self.exception = None

        self.conn_timeout = None

        if libtrace_uri.startswith('int'):
            self.source = (ipv4_address(self.libtrace_uri[4:]),
                           ipv6_address(self.libtrace_uri[4:]))
        else:
            self.source = ("127.0.0.1", "::1")

        self.__logger = logging.getLogger('pathspider')

    def config_zero(self):
        """
        Changes the global state or system configuration for the
        baseline measurements.
        """

        raise NotImplementedError("Cannot instantiate an abstract Spider")

    def config_one(self):
        """
        Changes the global state or system configuration for the
        experimental measurements.
        """

        raise NotImplementedError("Cannot instantiate an abstract Spider")

    def configurator(self):
        raise NotImplementedError("Cannot instantiate an abstract Spider")

    def worker(self, worker_number):
        raise NotImplementedError("Cannot instantiate an abstract Spider")

    def pre_connect(self, job):
        """
        Performs pre-connection operations.

        :param job: The job record
        :type job: dict

        The pre_connect function can be used to perform any operations that
        must be performed before each connection. It will be run only once
        per job, with the same result passed to both the A and B connect
        calls. This function is not synchronised with the configurator.

        Plugins to PATHspider can optionally implement this function. If this
        function is not overloaded, it will be a noop.
        """

        pass

    def _connect_wrapper(self, job, config):
        start = str(datetime.utcnow())
        conn = self.connect(job, config)
        conn['spdr_start'] = start
        return conn

    def connect(self, job, config):
        """
        Performs the connection.

        :param job: The job record.
        :type job: dict
        :param config: The current state of the configurator (0 or 1).
        :type config: int
        :returns: dict -- The result of the connect operation to be passed
                          to :func:`pathspider.base.Spider.post_connect`. This
                          dict must contain the necessary keys for the merger
                          to match the flow with the job and configuration.

        The connect function is used to perform the connection operation and
        is run for both the A and B test. This method is not implemented in
        the abstract :class:`pathspider.base.Spider` class and must be
        implemented by any plugin.

        Sockets created during this operation can be returned by the function
        for use in the post-connection phase, to minimise the time that the
        configurator is blocked from moving to the next configuration.
        """

        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def post_connect(self, job, rec, config):
        """
        Performs post-connection operations.

        :param job: The job record.
        :type job: dict
        :param rec: The result of the connection operation(s).
        :type rec: dict
        :param config: The state of the configurator during
                       :func:`pathspider.base.Spider.connect`.
        :type config: int

        The post_connect function can be used to perform any operations that
        must be performed after each connection. It will be run for both the
        A and the B configuration, and is not synchronised with the
        configurator.

        Plugins to PATHspider can optionally implement this function. If this
        function is not overloaded, it will be a noop.

        Any sockets or other file handles that were opened during
        :func:`pathspider.base.Spider.connect` should be closed in this
        function if they have not been already.
        """

        pass

    def create_observer(self):
        """
        Create a flow observer.

        This function is called by the base Spider logic to get an instance
        of :class:`pathspider.observer.Observer` configured with the function
        chains that are requried by the plugin.

        This method is not implemented in the abstract
        :class:`pathspider.base.Spider` class and must be implemented by any
        plugin.

        For more information on how to use the flow observer, see
        :ref:`Observer <observer>`.
        """

        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

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

        merging_flows = True
        merging_results = True

        while self.running and (merging_results or merging_flows):

            if merging_flows and self.flowqueue.qsize() >= self.resqueue.qsize():
                merging_flows = self._merge_flows()

            elif merging_results:
                merging_results = self._merge_results()

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

        if flow['jobId'] in self.comparetab:
            other_flow = self.comparetab.pop(flow['jobId'])
            flows = (flow, other_flow) if other_flow['config'] else (other_flow, flow)
            start = min(flow['spdr_start'], other_flow['spdr_start'])
            stop = max(flow['spdr_stop'], other_flow['spdr_stop'])
            job = self.jobtab.pop(flow['jobId'])
            job['flow_results'] = flows
            job['time'] = {'from': start, 'to': stop}
            job['conditions'] = self.combine_flows(flows)
            if job['conditions'] is None:
                job.pop('conditions')
            self.outqueue.put(job)
        else:
            self.comparetab[flow['jobId']] = flow

    def combine_flows(self, flows):
        pass

    def exception_wrapper(self, target, *args, **kwargs):
        try:
            target(*args, **kwargs)
        except: # pylint: disable=W0702
            self.__logger = logging.getLogger('pathspider')
            self.__logger.exception("exception occurred. terminating.")
            if self.exception is None:
                self.exception = sys.exc_info()[1]

            self.terminate()

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

        with self.lock:
            # set the running flag
            self.running = True

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
        Adds a job to the job queue.

        If PATHspider is currently stopping, the job will not be added to the
        queue.
        """

        if self.stopping:
            return

        self.jobqueue.put(job)

class PluggableSpider:
    @staticmethod
    def register_args(subparsers):
        raise NotImplementedError("Cannot register an abstract plugin")
