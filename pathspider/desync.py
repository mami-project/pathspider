import time
import logging
import queue
import uuid
from datetime import datetime

from pathspider.base import Spider
from pathspider.base import QUEUE_SLEEP
from pathspider.base import SHUTDOWN_SENTINEL


class DesynchronizedSpider(Spider):
    # pylint: disable=W0223

    connections = []

    def __init__(self, worker_count, libtrace_uri, args, server_mode=False):
        super().__init__(worker_count, libtrace_uri, args, server_mode)

        self.__logger = logging.getLogger('desync')

        self._config_count = len(self.connections) 

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
                    time.sleep(QUEUE_SLEEP)
                else:
                    # Hook for preconnection
                    self.pre_connect(job)

                    conns = []

                    for config in range(0, len(self.connections)):
                        conn = self._connect_wrapper(job, config,
                                                     connect=self.connections[config])
                        conns.append(conn)

                    # Save job record for combiner
                    self.jobtab[jobId] = job

                    # Pass results on for merge
                    self._finalise_conns(job, jobId, conns)

                    self.__logger.debug("job complete: " + repr(job))
                    self.jobqueue.task_done()
            elif not self.stopping:
                time.sleep(QUEUE_SLEEP)
            else:
                break

    @classmethod
    def register_args(cls, subparsers):
        # pylint: disable=no-member
        parser = subparsers.add_parser(cls.name, help=cls.description)
        parser.add_argument("--timeout", default=5, type=int,
                            help=("The timeout to use for attempted "
                                  "connections in seconds (Default: 5)"))
        parser.set_defaults(spider=cls)
        if hasattr(cls, "extra_args"):
            cls.extra_args(parser)
