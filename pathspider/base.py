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

from ipaddress import ip_address
from zope.interface import Interface

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

QUEUE_SIZE = 1000
QUEUE_SLEEP = 0.5

QOF_INITIAL_SLEEP = 3
QOF_FINAL_SLEEP = 3

class Spider:
    """
    A spider consists of a configurator (which alternates between two system
    configurations), a large number of workers (for performing some network
    action for each configuration), an Observer which derives information from
    passively observed traffic, and a thread that merges results from the
    workers with flow records from the collector.

    """

    def __init__(self):
        """
        Bare minimum initalisation for a pathspider plugin.

        .. warning::
         This function should not be overloaded by any plugin. Its purpose here
         is only to set the "activated" flag to false, to prevent the plugin
         functions being used before it has been activated.
        """

        self.activated = False

    def activate(self, worker_count, libtrace_uri, check_interrupt=None):
        """
        The activate function performs initialisation of a pathspider plugin.

        It is expected that this function will be overloaded by plugins, though
        the plugin should always make a call to the activate() function of the
        abstract Spider class as this initialises all of the base functionality.
        """

        self.activated = True
        self.running = False
        self.stopping = False
        self.terminating = False

        self.worker_count = worker_count
        self.libtrace_uri = libtrace_uri
        self.check_interrupt = check_interrupt

        self.sem_config_zero = SemaphoreN(worker_count)
        self.sem_config_zero.empty()
        self.sem_config_zero_rdy = SemaphoreN(worker_count)
        self.sem_config_zero_rdy.empty()
        self.sem_config_one = SemaphoreN(worker_count)
        self.sem_config_one.empty()
        self.sem_config_one_rdy = SemaphoreN(worker_count)
        self.sem_config_one_rdy.empty()

        self.jobqueue = queue.Queue(QUEUE_SIZE)
        self.flowqueue = mp.Queue(QUEUE_SIZE)
        self.resqueue = queue.Queue(QUEUE_SIZE)

        self.restab = {}
        self.flowtab = {}

        self.merged_results = collections.deque()

        self.observer = None

        self.worker_threads = []
        self.configurator_thread = None
        self.interrupter_thread = None
        self.merger_thread = None

        self.observer_process = None

        self.lock = threading.Lock()
        self.exception = None

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

    def config_zero(self):
        """
        Function to handle the global state or system configuration for the
        baseline measurements.
        """

        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def config_one(self):
        """
        Function to handle the global state or system configuration for the
        experimental measurements.
        """

        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def interrupter(self):
        if self.check_interrupt is None:
            return

        logger = logging.getLogger('pathspider')
        while self.running:
            if self.check_interrupt():
                logger.warning("spider interrupted")
                logger.warning("trying to abort %d jobs", self.jobqueue.qsize())
                while not self.jobqueue.empty():
                    self.jobqueue.get()
                    self.jobqueue.task_done()
                self.stop()
                break
            time.sleep(5)

    def worker(self):
        logger = logging.getLogger('pathspider')

        while self.running:
            try:
                job = self.jobqueue.get_nowait()
                logger.debug("got a job: "+repr(job))
            except queue.Empty:
                #logger.debug("no job available, sleeping")
                # spin the semaphores
                self.sem_config_zero.acquire()
                time.sleep(QUEUE_SLEEP)
                self.sem_config_one_rdy.release()
                self.sem_config_one.acquire()
                time.sleep(QUEUE_SLEEP)
                self.sem_config_zero_rdy.release()
            else:
                # Hook for preconnection
                pcs = self.pre_connect(job)

                # Wait for configuration zero
                self.sem_config_zero.acquire()

                # Connect in configuration zero
                conn0 = self.connect(job, pcs, 0)

                # Wait for configuration one
                self.sem_config_one_rdy.release()
                self.sem_config_one.acquire()

                # Connect in configuration one
                conn1 = self.connect(job, pcs, 1)

                # Signal okay to go to configuration zero
                self.sem_config_zero_rdy.release()

                # Pass results on for merge
                self.resqueue.put(self.post_connect(job, conn0, pcs, 0))
                self.resqueue.put(self.post_connect(job, conn1, pcs, 1))

                logger.debug("job complete: "+repr(job))
                self.jobqueue.task_done()

    def pre_connect(self, job):
        pass

    def connect(self, job, pcs, config):
        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def post_connect(self, job, conn, pcs, config):
        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def create_observer(self):
        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def merger(self):
        logger = logging.getLogger('pathspider')
        while self.running:
            if self.flowqueue.qsize() >= self.resqueue.qsize():
                try:
                    flow = self.flowqueue.get_nowait()
                except queue.Empty:
                    time.sleep(QUEUE_SLEEP)
                else:
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
                        self.flowtab[flowkey] = flow

                    self.flowqueue.task_done()
            else:
                try:
                    res = self.resqueue.get_nowait()
                except queue.Empty:
                    time.sleep(QUEUE_SLEEP)
                    logger.debug("result queue is empty")
                else:
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

    def merge(self, flow, res):
        raise NotImplementedError("Cannot instantiate an abstract Pathspider")

    def exception_wrapper(self, target, *args, **kwargs):
        try:
            target(*args, **kwargs)
        except:
            #FIXME: What exceptions do we expect?
            logger = logging.getLogger('pathspider')
            logger.exception("exception occurred. initiating termination and" +
                             "notify ecnspider component.")
            if self.exception is None:
                self.exception = sys.exc_info()[1]

            self.terminate()

    def run(self):
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
                      self.flowqueue),
                target=self.exception_wrapper,
                name='observer',
                daemon=True)
            self.observer_process.start()

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

            self.worker_threads = []
            for i in range(self.worker_count):
                worker_thread = threading.Thread(
                    args=(self.worker,),
                    target=self.exception_wrapper,
                    name='worker_{}'.format(i),
                    daemon=True)
                self.worker_threads.append(worker_thread)
                worker_thread.start()

            logger.debug("workers up")

            if self.check_interrupt is not None:
                self.interrupter_thread = threading.Thread(
                    args=(self.interrupter,),
                    target=self.exception_wrapper,
                    name="interrupter",
                    daemon=True)
                self.interrupter_thread.start()
                logger.debug("interrupter up")

    def terminate(self):
        if self.terminating:
            return

        self.terminating = True

        logger = logging.getLogger('pathspider')
        logger.error("terminating pathspider.")

        self.running = False

        self.join_threads()

        # empty all queues, so that stop() does not hang up.
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
                self.flowqueue.task_done()
        except ValueError:
            pass

        logger.error("termination complete. joined all threads, emptied all queues.")

    def join_threads(self):
        logger = logging.getLogger('pathspider')
        logger.debug("joining threads")
        for worker in self.worker_threads:
            if threading.current_thread() != worker:
                logger.debug("joining worker: " + repr(worker))
                worker.join()
        logger.debug("all workers joined")
        
        # FIXME okay to leave the observer process unjoined?
        # if threading.current_thread() != self.observer_thread:
        #     self.observer.interrupt()
        #     self.observer_thread.join()
        
        # logger.debug("observer joined")

        if threading.current_thread() != self.configurator_thread:
            self.configurator_thread.join()
        
        logger.debug("configurator joined")

        if (self.interrupter_thread is not None and
                threading.current_thread() != self.interrupter_thread):
            self.interrupter_thread.join()
        
        logger.debug("interrupter joined")

        if threading.current_thread() != self.merger_thread:
            self.merger_thread.join()
        
        logger.debug("merger joined")
        
        logger.debug("joining threads complete")

    def stop(self):
        logger = logging.getLogger('pathspider')

        logger.info("stopping pathspider")

        with self.lock:
            # Set stopping flag
            self.stopping = True

            # Wait for job and result queues to empty
            self.jobqueue.join()
            self.resqueue.join()
            logger.debug("job and result queues empty")

            # Wait for flow queue to empty
            self.flowqueue.join()
            logger.debug("flow queue empty")

            # Shut down threads
            self.running = False
            self.stopping = False

            # join threads
            self.join_threads()

    def add_job(self, job):
        if self.stopping or self.terminating:
            return

        self.jobqueue.put(job)

def local_address(ipv=4, target="path-ams.corvid.ch", port=53):
    if ipv == 4:
        addrfamily = socket.AF_INET
    elif ipv == 6:
        addrfamily = socket.AF_INET6
    else:
        assert False

    try:
        sock = socket.socket(addrfamily, socket.SOCK_DGRAM)
        sock.connect((target, port))
        return ip_address(sock.getsockname()[0])
    except:
        #FIXME: What exceptions do we expect?
        return None

class ISpider(Interface):
    """
    The ISpider class defines the expected interface for pathspider plugins.
    """

    def activate(self, worker_count, libtrace_uri, check_interrupt=None):
        """
        This method should initialise the spider class. It should always begin
        with a call to the superclass' activate() method if this is overloaded:

        .. code-block:: python

         super().activate(worker_count=worker_count,
                          libtrace_uri=libtrace_uri,
                          check_interrupt=check_interrupt)

        This can be used to initialise any variables which may be required in
        the object. Do not initialise any variables in the __init__ method, or
        perform any other operations there as all plugins must be instantiated
        in order to be loaded and this will cause unnecessary delays in the
        starting of pathspider.
        """

    def config_zero(self):
        pass

    def config_one(self):
        pass

    def pre_connect(self, job):
        pass

    def connect(self, job, pcs, config):
        pass

    def post_connect(self, job, conn, pcs, config):
        pass

    def create_observer(self):
        pass

    def merger(self):
        pass

    def merge(self, flow, res):
        pass

    def exception_wrapper(self, target, *args, **kwargs):
        pass

    def run(self):
        pass

    def terminate(self):
        pass

    def join_threads(self):
        pass

    def stop(self):
        pass

    def add_job(self, job):
        pass

