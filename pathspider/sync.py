import logging
import queue
import threading
import time
import uuid

from pathspider.base import Spider
from pathspider.base import QUEUE_SLEEP
from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.helpers.tcp import connect_tcp
from pathspider.helpers.http import connect_http
from pathspider.helpers.http import connect_https
from pathspider.helpers.dns import connect_dns_tcp
from pathspider.helpers.dns import connect_dns_udp
from pathspider.base import CONN_DISCARD

class SynchronizedSpider(Spider):
    # pylint: disable=W0223

    configurations = []

    def __init__(self, worker_count, libtrace_uri, args, server_mode=False):
        super().__init__(worker_count, libtrace_uri, args, server_mode)
        self.__logger = logging.getLogger('sync')

        self._config_count = len(self.configurations)

        self.__semaphores = []

        # create semaphores for synchronizing configurations
        for config in range(0, len(self.configurations)):
            self.__semaphores.append([])
            for i in range(0, 2):
                self.__semaphores[config].append(SemaphoreN(worker_count))
                self.__semaphores[config][i].empty()

    def configurator(self):
        """
        Thread which synchronizes on a set of semaphores and alternates
        between two system states.
        """

        while self.running:
            for config in range(0, len(self.configurations)):
                self.__logger.debug("setting config %d", config)
                self.configurations[config](self)
                self.__logger.debug("config %d active", config)
                self.__semaphores[config][0].release_n(self.worker_count)
                self.__semaphores[(config + 1) % len(self.configurations)][
                    1].acquire_n(self.worker_count)

        # In case the master exits the run loop before all workers have,
        # these tokens will allow all workers to run through again,
        # until the next check at the start of the loop
        for config in range(0, len(self.configurations)):
            self.__semaphores[config][0].release_n(self.worker_count)

    def connect(self, job, config): # pylint: disable=unused-argument
        """
        Performs the requested connection.
        """

        if self.args.connect == "tcp":
            rec = connect_tcp(self.source, job, self.args.timeout)
        elif self.args.connect == "http":
            rec = connect_http(self.source, job, self.args.timeout)
        elif self.args.connect == "https":
            rec = connect_https(self.source, job, self.args.timeout)
        elif self.args.connect == "dnstcp":
            rec = connect_dns_tcp(self.source, job, self.args.timeout)
        elif self.args.connect == "dnsudp":
            rec = connect_dns_udp(self.source, job, self.args.timeout)
        else:
            raise RuntimeError("Unknown connection type requested!")

        return rec

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
                        self.__logger.debug(
                            "shutting down worker %d on sentinel",
                            worker_number)
                        worker_active = False
                        with self.active_worker_lock:
                            self.active_worker_count -= 1
                            self.__logger.debug("%d workers still active",
                                                self.active_worker_count)
                        continue

                    self.__logger.debug("got a job: " + repr(job))
                except queue.Empty:
                    #logger.debug("no job available, sleeping")
                    # spin the semaphores
                    for config in range(0, len(self.configurations)):
                        self.__semaphores[config][0].acquire()
                        time.sleep(QUEUE_SLEEP)
                        self.__semaphores[(config + 1) % len(
                            self.configurations)][1].release()
                else:
                    # Hook for preconnection
                    self.pre_connect(job)

                    conns = []
                    should_discard = False

                    for config in range(0, len(self.configurations)):
                        # Wait for configuration
                        self.__semaphores[config][0].acquire()

                        # Connect in configuration
                        conn = self._connect_wrapper(job, config)
                        if 'spdr_state' in conn:
                            if conn['spdr_state'] == CONN_DISCARD:
                                should_discard = True
                        conns.append(conn)

                        # Wait for next configuration
                        self.__semaphores[(config + 1) % len(
                            self.configurations)][1].release()

                    if not should_discard:
                        # Save job record for combiner
                        self.jobtab[jobId] = job

                        # Finish connections and pass on for merging
                        self._finalise_conns(job, jobId, conns)

                    self.__logger.debug("job complete: " + repr(job))
                    self.jobqueue.task_done()
            else:  # not worker_active, spin the semaphores
                for config in range(0, len(self.configurations)):
                    self.__semaphores[config][0].acquire()
                    time.sleep(QUEUE_SLEEP)
                    if config == 0:
                        with self.active_worker_lock:
                            if self.active_worker_count <= 0:
                                return
                    self.__semaphores[(config + 1) % len(self.configurations)][
                        1].release()

    @classmethod
    def register_args(cls, subparsers):
        # pylint: disable=no-member
        parser = subparsers.add_parser(cls.name, help=cls.description)
        parser.set_defaults(spider=cls)
        parser.add_argument("--connect", type=str, choices=cls.connect_supported,
                            default=cls.connect_supported[0],
                            metavar="[{}]".format("|".join(cls.connect_supported)),
                            help="Type of connection to perform (Default: {})".format(
                                cls.connect_supported[0]))
        parser.add_argument("--timeout", default=5, type=int,
                            help=("The timeout to use for attempted connections in seconds "
                                  "(Default: 5)"))
        if hasattr(cls, "extra_args"):
            cls.extra_args(parser)


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
