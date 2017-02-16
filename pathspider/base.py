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
import socket
import collections
import threading
import multiprocessing as mp
import queue
from datetime import datetime
from enum import Enum

from ipaddress import ip_address

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

class Conn(Enum):
    OK = 0
    FAILED = 1
    TIMEOUT = 2
    SKIPPED = 3

Connection = collections.namedtuple("Connection", ["client", "port", "state", "tstart"])

QUEUE_SIZE = 1000
QUEUE_SLEEP = 0.5

SHUTDOWN_SENTINEL = "SHUTDOWN_SENTINEL"
NO_RESULT = None
NO_FLOW = None

class Spider:
    """
    A spider consists of a configurator (which alternates between two system
    configurations), a large number of workers (for performing some network
    action for each configuration), an Observer which derives information from
    passively observed traffic, and a thread that merges results from the
    workers with flow records from the collector.

    """

    def __init__(self, worker_count, libtrace_uri, args):
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

        self.activated = True
        self.running = False
        self.stopping = False
        self.terminating = False

        self.worker_count = worker_count
        self.active_worker_count = 0
        self.active_worker_lock = threading.Lock()

        self.libtrace_uri = libtrace_uri

        self.jobqueue = queue.Queue(QUEUE_SIZE)
        self.resqueue = queue.Queue(QUEUE_SIZE)

        self.flowqueue = mp.Queue(QUEUE_SIZE)
        self.observer_shutdown_queue = mp.Queue(QUEUE_SIZE)

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

        # self._worker_state = [ "not_started" ] * self.worker_count

        self.lock = threading.Lock()
        self.exception = None

        self.conn_timeout = None

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

    def worker(self):
        raise NotImplementedError("Cannot instantiate an abstract Spider")

    def pre_connect(self, job):
        """
        Performs pre-connection operations.

        :param job: The job record.
        :type job: dict
        :returns: dict -- Result of the pre-connection operation(s).

        The pre_connect function can be used to perform any operations that
        must be performed before each connection. It will be run only once
        per job, with the same result passed to both the A and B connect
        calls. This function is not synchronised with the configurator.

        Plugins to PATHspider can optionally implement this function. If this
        function is not overloaded, it will be a noop.
        """

        pass

    def connect(self, job, pcs, config):
        """
        Performs the connection.

        :param job: The job record.
        :type job: dict
        :param pcs: The result of the pre-connection operations(s).
        :type pcs: dict
        :param config: The current state of the configurator (0 or 1).
        :type config: int
        :returns: object -- Any result of the connect operation to be passed
                            to :func:`pathspider.base.Spider.post_connect`.

        The connect function is used to perform the connection operation and
        is run for both the A and B test. This method is not implemented in
        the abstract :class:`pathspider.base.Spider` class and must be
        implemented by any plugin.

        Sockets created during this operation can be returned by the function
        for use in the post-connection phase, to minimise the time that the
        configurator is blocked from moving to the next configuration.
        """

        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def post_connect(self, job, conn, pcs, config):
        """
        Performs post-connection operations.

        :param job: The job record.
        :type job: dict
        :param conn: The result of the connection operation(s).
        :type conn: object
        :param pcs: The result of the pre-connection operations(s).
        :type pcs: dict
        :param config: The state of the configurator during
                       :func:`pathspider.base.Spider.connect`.
        :type config: int
        :returns: dict -- Result of the pre-connection operation(s).

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

        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

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

    def merger(self):
        """
        Thread to merge results from the workers and the observer.
        """

        logger = logging.getLogger('pathspider')
        merging_flows = True
        merging_results = True

        # merge_cycles = 0

        while self.running and (merging_results or merging_flows):

            # if merge_cycles % 20 == 0:
            #     for wn in range(0, self.worker_count):
            #         logger.debug("worker %3u: %s" % (wn, self._worker_state[wn]))
            # merge_cycles += 1

            if merging_flows and self.flowqueue.qsize() >= self.resqueue.qsize():
                try:
                    flow = self.flowqueue.get_nowait()
                except queue.Empty:
                    time.sleep(QUEUE_SLEEP)
                else:
                    if flow == SHUTDOWN_SENTINEL:
                        logger.debug("stopping flow merging on sentinel")
                        merging_flows = False
                        continue

                    flowkey = (flow['dip'], flow['sp'])
                    logger.debug("got a flow (" + str(flow['sip']) + ", " +
                                 str(flow['sp']) + ")")

                    if flowkey in self.restab:
                        logger.debug("merging flow")
                        self.merge(flow, self.restab[flowkey])
                        del self.restab[flowkey]
                    elif flowkey in self.flowtab:
                        logger.debug("won't merge duplicate flow")
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

            elif merging_results:
                try:
                    res = self.resqueue.get_nowait()
                except queue.Empty:
                    time.sleep(QUEUE_SLEEP)
                    logger.debug("result queue is empty")
                else:
                    if res == NO_RESULT:
                        # handle skipped results
                        continue
                    if res == SHUTDOWN_SENTINEL:
                        merging_results = False
                        logger.debug("stopping result merging on sentinel")
                        continue

                    reskey = (res.ip, res.port)
                    logger.debug("got a result (" + str(res.ip) + ", " +
                                 str(res.port) + ")")

                    if reskey in self.flowtab:
                        logger.debug("merging result")
                        self.merge(self.flowtab[reskey], res)
                        del self.flowtab[reskey]
                    elif reskey in self.restab:
                        logger.debug("won't merge duplicate result")
                    else:
                        self.restab[reskey] = res

                    self.resqueue.task_done()

        # Both shutdown markers received.
        # Call merge on all remaining entries in the results table
        # with null flows.
        # Commented out for now; see https://github.com/mami-project/pathspider/issues/29
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

        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def exception_wrapper(self, target, *args, **kwargs):
        try:
            target(*args, **kwargs)
        except:
            #FIXME: What exceptions do we expect?
            logger = logging.getLogger('pathspider')
            logger.exception("exception occurred. terminating.")
            if self.exception is None:
                self.exception = sys.exc_info()[1]

            self.terminate()

    def start(self):
        """
        This function starts a PATHspider plugin.

        In order to run, the plugin must have first been activated by calling
        its :func:`activate` method. This function causes the following to
        happen:

         * Set the running flag
         * Create an :class:`pathspider.observer.Observer` and start its
           process
         * Start the merger thread
         * Start the configurator thread
         * Start the worker threads

        The number of worker threads to start was given when activating the
        plugin.
        """

        logger = logging.getLogger('pathspider')
        if self.activated == False:
            logger.exception("tried to run plugin without activating first")
            sys.exit(1)

        logger.info("starting pathspider")

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
            logger.debug("observer forked")

            # now start up ecnspider, backwards
            self.merger_thread = threading.Thread(
                args=(self.merger,),
                target=self.exception_wrapper,
                name="merger",
                daemon=True)
            self.merger_thread.start()
            logger.debug("merger up")

            self.configurator_thread = threading.Thread(
                args=(self.configurator,),
                target=self.exception_wrapper,
                name="configurator",
                daemon=True)
            self.configurator_thread.start()
            logger.debug("configurator up")

            # threading.Thread(
            #     target = self.worker_status_reporter,
            #     name = "status_reporter",
            #     daemon = True).start()
            # logger.debug("status reporter up")

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
            logger.debug("workers up")

    def shutdown(self):
        """
        Shut down PathSpider in an orderly fashion,
        ensuring that all queued jobs complete,
        and all available results are merged.

        """
        logger = logging.getLogger('pathspider')

        logger.info("beginning shutdown")

        with self.lock:
            # Set stopping flag
            self.stopping = True

            # Put a bunch of shutdown signals in the job queue
            for i in range(self.worker_count * 2):
                self.jobqueue.put(SHUTDOWN_SENTINEL)

            # Wait for worker threads to shut down
            for worker in self.worker_threads:
                if threading.current_thread() != worker:
                    logger.debug("joining worker: " + repr(worker))
                    worker.join()
            logger.debug("all workers joined")

            # Tell observer to shut down
            self.observer_shutdown_queue.put(True)
            self.observer_process.join()
            logger.debug("observer shutdown")

            # Tell merger to shut down
            self.resqueue.put(SHUTDOWN_SENTINEL)
            self.merger_thread.join()
            logger.debug("merger shutdown")

            # Wait for merged results to be written
            self.outqueue.join()
            logger.debug("all results retrieved")

            # Propagate shutdown sentinel and tell threads to stop
            self.outqueue.put(SHUTDOWN_SENTINEL)

            # Tell threads we've stopped
            self.running = False

            # Join configurator
            # if threading.current_thread() != self.configurator_thread:
            #     self.configurator_thread.join()

            self.stopping = False

        logger.info("shutdown complete")

    def terminate(self):
        """
        Shut down PathSpider as quickly as possible,
        without any regard to completeness of results.

        """
        logger = logging.getLogger('pathspider')
        logger.info("terminating pathspider")

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
                logger.debug("joining worker: " + repr(worker))
                worker.join()
        logger.debug("all workers joined")

        if self.configurator_thread and \
                (threading.current_thread() != self.configurator_thread):
            self.configurator_thread.join()
            logger.debug("configurator joined")

        if threading.current_thread() != self.merger_thread:
            self.merger_thread.join()
            logger.debug("merger joined")

        self.observer_process.join()
        logger.debug("observer joined")

        self.outqueue.put(SHUTDOWN_SENTINEL)
        logger.info("termination complete")

    def add_job(self, job):
        """
        Adds a job to the job queue.

        If PATHspider is currently stopping, the job will not be added to the
        queue.
        """

        if self.stopping:
            return

        self.jobqueue.put(job)


class SynchronizedSpider(Spider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count, libtrace_uri, args)

        # create semaphores for synchronizing configurations
        self.sem_config_zero = SemaphoreN(worker_count)
        self.sem_config_zero.empty()
        self.sem_config_zero_rdy = SemaphoreN(worker_count)
        self.sem_config_zero_rdy.empty()
        self.sem_config_one = SemaphoreN(worker_count)
        self.sem_config_one.empty()
        self.sem_config_one_rdy = SemaphoreN(worker_count)
        self.sem_config_one_rdy.empty()

    def configurator(self):
        """
        Thread which synchronizes on a set of semaphores and alternates
        between two system states.
        """
        logger = logging.getLogger('pathspider')

        while self.running:
            logger.debug("setting config zero")
            self.config_zero()
            logger.debug("config zero active")
            self.sem_config_zero.release_n(self.worker_count)
            self.sem_config_one_rdy.acquire_n(self.worker_count)
            logger.debug("setting config one")
            self.config_one()
            logger.debug("config one active")
            self.sem_config_one.release_n(self.worker_count)
            self.sem_config_zero_rdy.acquire_n(self.worker_count)

        # In case the master exits the run loop before all workers have,
        # these tokens will allow all workers to run through again,
        # until the next check at the start of the loop
        self.sem_config_zero.release_n(self.worker_count)
        self.sem_config_one.release_n(self.worker_count)

    def worker(self, worker_number):
        """
        This function provides the logic for
        configuration-synchronized worker threads.

        :param worker_number: The unique number of the worker.
        :type worker_number: int

        The workers operate as continuous loops:

         * Fetch next job from the job queue
         * Perform pre-connection operations
         * Acquire a lock for "config_zero"
         * Perform the "config_zero" connection
         * Release "config_zero"
         * Acquire a lock for "config_one"
         * Perform the "config_one" connection
         * Release "config_one"
         * Perform post-connection operations for config_zero and pass the
           result to the merger
         * Perform post-connection operations for config_one and pass the
           result to the merger
         * Do it all again

        If the job fetched is the SHUTDOWN_SENTINEL, then the worker will
        terminate as this indicates that all the jobs have now been processed.
        """

        logger = logging.getLogger('pathspider')
        worker_active = True

        while self.running:
            if worker_active:
                try:
                    job = self.jobqueue.get_nowait()

                    # Break on shutdown sentinel
                    if job == SHUTDOWN_SENTINEL:
                        self.jobqueue.task_done()
                        logger.debug("shutting down worker "+str(worker_number)+" on sentinel")
                        # self._worker_state[worker_number] = "shutdown_sentinel"
                        worker_active = False
                        with self.active_worker_lock:
                            self.active_worker_count -= 1
                            logger.debug(str(self.active_worker_count)+" workers still active")
                        continue

                    logger.debug("got a job: "+repr(job))
                except queue.Empty:
                    #logger.debug("no job available, sleeping")
                    # spin the semaphores
                    self.sem_config_zero.acquire()
                    # self._worker_state[worker_number] = "sleep_0"
                    time.sleep(QUEUE_SLEEP)
                    self.sem_config_one_rdy.release()
                    self.sem_config_one.acquire()
                    # self._worker_state[worker_number] = "sleep_1"
                    time.sleep(QUEUE_SLEEP)
                    self.sem_config_zero_rdy.release()
                else:
                    # Hook for preconnection
                    # self._worker_state[worker_number] = "preconn"
                    pcs = self.pre_connect(job)

                    # Wait for configuration zero
                    # self._worker_state[worker_number] = "wait_0"
                    self.sem_config_zero.acquire()

                    # Connect in configuration zero
                    # self._worker_state[worker_number] = "conn_0"
                    conn0 = self.connect(job, pcs, 0)

                    # Wait for configuration one
                    # self._worker_state[worker_number] = "wait_1"
                    self.sem_config_one_rdy.release()
                    self.sem_config_one.acquire()

                    # Connect in configuration one
                    # self._worker_state[worker_number] = "conn_1"
                    conn1 = self.connect(job, pcs, 1)

                    # Signal okay to go to configuration zero
                    self.sem_config_zero_rdy.release()

                    # Pass results on for merge
                    # self._worker_state[worker_number] = "postconn_0"
                    self.resqueue.put(self.post_connect(job, conn0, pcs, 0))
                    # self._worker_state[worker_number] = "postconn_1"
                    self.resqueue.put(self.post_connect(job, conn1, pcs, 1))

                    # self._worker_state[worker_number] = "done"
                    logger.debug("job complete: "+repr(job))
                    self.jobqueue.task_done()
            else: # not worker_active, spin the semaphores
                self.sem_config_zero.acquire()
                # self._worker_state[worker_number] = "shutdown_0"
                time.sleep(QUEUE_SLEEP)
                with self.active_worker_lock:
                    if self.active_worker_count <= 0:
                        # self._worker_state[worker_number] = "shutdown_complete"
                        break
                self.sem_config_one_rdy.release()
                self.sem_config_one.acquire()
                # self._worker_state[worker_number] = "shutdown_1"
                time.sleep(QUEUE_SLEEP)
                self.sem_config_zero_rdy.release()

    def tcp_connect(self, job):
        """
        This helper function will perform a TCP connection. It will not perform
        any special action in the event that this is the experimental flow,
        it only performs a TCP connection. This function expects that
        self.conn_timeout has been set to a sensible value.
        """

        if self.conn_timeout is None:
            raise RuntimeError("Plugin did not set TCP connect timeout.")

        tstart = str(datetime.utcnow())

        if ":" in job[0]:
            sock = socket.socket(socket.AF_INET6)
        else:
            sock = socket.socket(socket.AF_INET)

        try:
            sock.settimeout(self.conn_timeout)
            sock.connect((job[0], job[1]))

            return Connection(sock, sock.getsockname()[1], Conn.OK, tstart)
        except TimeoutError:
            return Connection(sock, sock.getsockname()[1], Conn.TIMEOUT, tstart)
        except OSError:
            return Connection(sock, sock.getsockname()[1], Conn.FAILED, tstart)


class DesynchronizedSpider(Spider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count, libtrace_uri, args)

    def config_zero(self):
        pass

    def config_one(self):
        pass

    def configurator(self):
        """
        Since there is no need for a configurator thread in a
        desynchronized spider, this thread is a no-op
        """
        logger = logging.getLogger('pathspider')
        logger.info("configurations are not synchronized")

    def worker(self, worker_number):
        """
        This function provides the logic for
        configuration-synchronized worker threads.

        :param worker_number: The unique number of the worker.
        :type worker_number: int

        The workers operate as continuous loops:

         * Fetch next job from the job queue
         * Perform pre-connection operations
         * Acquire a lock for "config_zero"
         * Perform the "config_zero" connection
         * Release "config_zero"
         * Acquire a lock for "config_one"
         * Perform the "config_one" connection
         * Release "config_one"
         * Perform post-connection operations for config_zero and pass the
           result to the merger
         * Perform post-connection operations for config_one and pass the
           result to the merger
         * Do it all again

        If the job fetched is the SHUTDOWN_SENTINEL, then the worker will
        terminate as this indicates that all the jobs have now been processed.
        """

        logger = logging.getLogger('pathspider')
        worker_active = True

        while self.running:
            if worker_active:
                try:
                    job = self.jobqueue.get_nowait()

                    # Break on shutdown sentinel
                    if job == SHUTDOWN_SENTINEL:
                        self.jobqueue.task_done()
                        logger.debug("shutting down worker "+str(worker_number)+" on sentinel")
                        # self._worker_state[worker_number] = "shutdown_sentinel"
                        worker_active = False
                        with self.active_worker_lock:
                            self.active_worker_count -= 1
                            logger.debug(str(self.active_worker_count)+" workers still active")
                        continue

                    logger.debug("got a job: "+repr(job))
                except queue.Empty:
                    time.sleep(QUEUE_SLEEP)
                else:
                    # Hook for preconnection
                    # self._worker_state[worker_number] = "preconn"
                    pcs = self.pre_connect(job)

                    # Connect in configuration zero
                    # self._worker_state[worker_number] = "conn_0"
                    conn0 = self.connect(job, pcs, 0)

                    # Connect in configuration one
                    # self._worker_state[worker_number] = "conn_1"
                    conn1 = self.connect(job, pcs, 1)

                    # Pass results on for merge
                    # self._worker_state[worker_number] = "postconn_0"
                    self.resqueue.put(self.post_connect(job, conn0, pcs, 0))
                    # self._worker_state[worker_number] = "postconn_1"
                    self.resqueue.put(self.post_connect(job, conn1, pcs, 1))

                    # self._worker_state[worker_number] = "done"
                    logger.debug("job complete: "+repr(job))
                    self.jobqueue.task_done()
            elif not self.stopping:
                time.sleep(QUEUE_SLEEP)
            else:
                # self._worker_state[worker_number] = "shutdown_complete"
                break

class PluggableSpider:
    @staticmethod
    def register_args(subparsers):
        raise NotImplementedError("Cannot register an abstract plugin")
