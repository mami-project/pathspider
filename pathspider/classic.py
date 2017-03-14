import time
import logging
import socket
import threading
import multiprocessing as mp
import queue
import uuid
from datetime import datetime

from pathspider.base import SemaphoreN
from pathspider.base import Spider
from pathspider.base import CONN_OK
from pathspider.base import CONN_FAILED
from pathspider.base import CONN_TIMEOUT
from pathspider.base import QUEUE_SLEEP
from pathspider.base import SHUTDOWN_SENTINEL

class SynchronizedSpider(Spider):

    def __init__(self, worker_count, libtrace_uri, args, server_mode=False):
        super().__init__(worker_count, libtrace_uri, args, server_mode)
        self.__logger = logging.getLogger('sync')

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

        while self.running:
            self.__logger.debug("setting config zero")
            self.config_zero()
            self.__logger.debug("config zero active")
            self.sem_config_zero.release_n(self.worker_count)
            self.sem_config_one_rdy.acquire_n(self.worker_count)
            self.__logger.debug("setting config one")
            self.config_one()
            self.__logger.debug("config one active")
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

        worker_active = True

        while self.running:
            if worker_active:
                try:
                    job = self.jobqueue.get_nowait()
                    jobId = uuid.uuid1().hex

                    # Break on shutdown sentinel
                    if job == SHUTDOWN_SENTINEL:
                        self.jobqueue.task_done()
                        self.__logger.debug("shutting down worker %d on sentinel",
                                            worker_number)
                        worker_active = False
                        with self.active_worker_lock:
                            self.active_worker_count -= 1
                            self.__logger.debug("%d workers still active",
                                                self.active_worker_count)
                        continue

                    self.__logger.debug("got a job: "+repr(job))
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
                    self.pre_connect(job)

                    # Wait for configuration zero
                    self.sem_config_zero.acquire()

                    # Connect in configuration zero
                    conn0 = self._connect_wrapper(job, 0)

                    # Wait for configuration one
                    self.sem_config_one_rdy.release()
                    self.sem_config_one.acquire()

                    # Connect in configuration one
                    conn1 = self._connect_wrapper(job, 1)

                    # Signal okay to go to configuration zero
                    self.sem_config_zero_rdy.release()

                    # Save job record for combiner
                    self.jobtab[jobId] = job

                    # Pass results on for merge
                    config = 0
                    for conn in [conn0, conn1]:
                        self.post_connect(job, conn, config)
                        conn['spdr_stop'] = str(datetime.utcnow())
                        conn['config'] = config
                        if self.server_mode:
                            conn['sip'] = job['sip']
                        else:
                            conn['dip'] = job['dip']
                        conn['jobId'] = jobId
                        self.resqueue.put(conn)
                        config += 1

                    self.__logger.debug("job complete: "+repr(job))
                    self.jobqueue.task_done()
            else: # not worker_active, spin the semaphores
                self.sem_config_zero.acquire()
                time.sleep(QUEUE_SLEEP)
                with self.active_worker_lock:
                    if self.active_worker_count <= 0:
                        break
                self.sem_config_one_rdy.release()
                self.sem_config_one.acquire()
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

        if ":" in job['dip']:
            sock = socket.socket(socket.AF_INET6)
        else:
            sock = socket.socket(socket.AF_INET)

        try:
            sock.settimeout(self.conn_timeout)
            sock.connect((job['dip'], job['dp']))

            return {'client': sock, 'sp': sock.getsockname()[1], 'spdr_state': CONN_OK}
        except TimeoutError:
            return {'client': sock, 'sp': sock.getsockname()[1], 'spdr_state': CONN_TIMEOUT}
        except OSError:
            return {'client': sock, 'sp': sock.getsockname()[1], 'spdr_state': CONN_FAILED}


class DesynchronizedSpider(Spider):

    def __init__(self, worker_count, libtrace_uri, args, server_mode=False):
        super().__init__(worker_count, libtrace_uri, args, server_mode)
        self.__logger = logging.getLogger('desync')

    def config_zero(self):
        pass

    def config_one(self):
        pass

    def configurator(self):
        """
        Since there is no need for a configurator thread in a
        desynchronized spider, this thread is a no-op
        """
        self.__logger.info("configurations are not synchronized")

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

        worker_active = True

        while self.running:
            if worker_active:
                try:
                    job = self.jobqueue.get_nowait()
                    jobId = uuid.uuid1().hex

                    # Break on shutdown sentinel
                    if job == SHUTDOWN_SENTINEL:
                        self.jobqueue.task_done()
                        self.__logger.debug("shutting down worker %d on sentinel",
                                            worker_number)
                        worker_active = False
                        with self.active_worker_lock:
                            self.active_worker_count -= 1
                            self.__logger.debug("%d workers still active",
                                                self.active_worker_count)
                        continue

                    self.__logger.debug("got a job: "+repr(job))
                except queue.Empty:
                    time.sleep(QUEUE_SLEEP)
                else:
                    # Hook for preconnection
                    self.pre_connect(job)

                    # Connect in configuration zero
                    conn0 = self._connect_wrapper(job, 0)

                    # Connect in configuration one
                    conn1 = self._connect_wrapper(job, 1)

                    # Save job record for combiner
                    self.jobtab[jobId] = job

                    # Pass results on for merge
                    config = 0
                    for conn in [conn0, conn1]:
                        self.post_connect(job, conn, config)
                        conn['spdr_stop'] = str(datetime.utcnow())
                        conn['config'] = config
                        conn['dip'] = job['dip']
                        conn['dp'] = job['dp']
                        conn['jobId'] = jobId
                        self.resqueue.put(conn)
                        config += 1

                    self.__logger.debug("job complete: "+repr(job))
                    self.jobqueue.task_done()
            elif not self.stopping:
                time.sleep(QUEUE_SLEEP)
            else:
                break
