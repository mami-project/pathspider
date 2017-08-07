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
from scapy.all import *

from pathspider.network import ipv4_address
from pathspider.network import ipv6_address

__version__ = "2.0.0.dev0"

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2
CONN_SKIPPED = 3
CONN_DISCARD = 4

PORT_FAILED = 0
PORT_FAILED_AGAIN = -1

QUEUE_SIZE = 1000
QUEUE_SLEEP = 0.5

INITIAL_PORT = 10000
INITIAL_SEQ = 10000

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

    chains = [] # Disable the observer by default

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
        self.ipqueue = mp.Queue(QUEUE_SIZE)
        self.tracemergequeue = queue.Queue(QUEUE_SIZE)
        self.sendresqueue = queue.Queue(QUEUE_SIZE)

        self.jobtab = {}
        self.comparetab = {}
        self.restab = {}
        self.flowtab = {}
        self.flowreap = collections.deque()
        self.flowreap_size = min(self.worker_count * 100, 10000)

        self.outqueue = queue.Queue(QUEUE_SIZE)
        self.traceoutqueue = queue.Queue(QUEUE_SIZE)

        self.observer = None

        self.worker_threads = []
        self.configurator_thread = None
        self.merger_thread = None

        self.observer_process = None

        self.lock = threading.Lock()
        self.exception = None

        if libtrace_uri.startswith('int'):
            self.source = (ipv4_address(self.libtrace_uri[4:]),
                           ipv6_address(self.libtrace_uri[4:]))
        else:
            self.source = ("127.0.0.1", "::1")

        self.__logger = logging.getLogger('pathspider')

        if hasattr(self.args, 'connect') and self.args.connect.startswith('tor'):
            logging.getLogger("stem").setLevel(logging.ERROR)
            import stem.control
            self.controller = stem.control.Controller.from_port()
            self.controller.authenticate()


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
             
            # If flow has trace flag set send it to traceroute merger
            if flow['trace'] == True:
                self.tracemergequeue.put(flow)
                return True           
            
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

        if len(self.chains) > 0:
            merging_flows = True
        else:
            merging_flows = False
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
            job['conditions'] = self.combine_flows(flows)
            if job['conditions'] is None:
                job.pop('conditions')
            if "ecn.negotiation.failed" in job['conditions']: #TODO make changeable
                dip = job['dip']
                self.ipqueue.put(dip)
            self.outqueue.put(job)

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

    def _finalise_conns(self, job, jobId, conns):
        # Pass results on for merge
        config = 0
        for conn in conns:
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
            
    def sender(self):
        """Send TCP packet with increasing TTL for every hop to destination"""
    
        #TODO integrate TTL and src for number of flows
        hops_add = 3        # buffer for additional hops
        hops = 25 + hops_add
        src = 1
        self.__logger.debug("Sender started")
        while True:
            try:
                dip = self.ipqueue.get_nowait()
            except queue.Empty:
                time.sleep(QUEUE_SLEEP)
                self.__logger.debug("IP queue is empty")
            else:
                if dip == SHUTDOWN_SENTINEL:
                    break
                else:
                    for j in range(src):    #repeating with src different flows  
                        for i in range(hops):                   
                            if ':' in dip: #IPv6
                                pass   #since not working correctly at the moment
                                #send(IPv6(hlim=(i+1), tc=0,dst = dip)/TCP(seq=(INITIAL_SEQ+i),sport = (INITIAL_PORT+j), flags = 0xc2), verbose=0)
                            else:
                                send(IP(ttl=(i+1),dst = dip, tos = 0x00)/TCP(seq=(INITIAL_SEQ+i),sport = (INITIAL_PORT+j), flags = 0xc2), verbose=0, inter=0.1)    
                        time.sleep(0.25)
                        self.__logger.info(("Sending flow %u of %s finished "), (j+1), dip)
        
    def trace_merger(self):
        
        while True:  # TODO try with except value error???
            res = self.tracemergequeue.get()
        
            self.__logger.debug("MERGERMERGERMGERGER %s", res)
            
            for entry in res.copy():
                if entry.isdigit(): 
                    for entry2 in res.copy():
                        diff = bytearray()
                        if entry2.isdigit():
                            if (int(entry)+9999) == int(entry2):  #comparing sequencenumber of upstream entry2 with hopnumber of downstream entry
                                rtt= (res[entry][1]- res[entry2][0])*1000
                                rtt = round(rtt,3)
                        
                                """bytearray comparison """
                                length = int(len(res[entry][3])/2-1)
                                fail = []
                                for i in range(length): #TODO whats the problem with the length... why isnt it working ?
                                    try:
                                        bts = res[entry][3][i]^res[entry2][1][i]
                                        diff = diff + bts.to_bytes(1, byteorder='big')
                                    except IndexError:
                                        pass
                                    else:
                                        if bts != 0:# and i != 8 and i != 10 and i != 11:  #check for differences beside ttl and checksum
                                            fail.append("%d: %d" % (i, bts))
                                
                                    
                                res[entry] = [res[entry][0], rtt, res[entry][2], res[entry][4], res[entry][5], res[entry][6], res[entry][7], res[entry][8], str(fail)]
                                del res[entry2]
    
            # remove sequence number entries that have not been used                
            for entrytest in res.copy():
                try:
                    if int(entrytest) > 100:
                        del res[entrytest]
                except ValueError:
                    pass
                        
            self.traceoutqueue.put(res.copy())
            

    def start(self, trace):
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
            
            if trace:
                self.trace_merger_thread = threading.Thread(
                    args=(self.trace_merger,),
                    target=self.exception_wrapper,
                    name="trace_merger",
                    daemon=True)
                self.trace_merger_thread.start()
                self.__logger.debug("traceroute-merger up")
                
                self.packet_sender_process = mp.Process(
                    args=(self.sender,),
                    target=self.exception_wrapper,
                    name='packet_sender',
                    daemon=True)
                self.packet_sender_process.start()
                self.__logger.debug("packet-sender up")
            
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

            #self.packet_sender_process.join()
            
            time.sleep(25)
            
            # Tell observer to shut down
            self.observer_shutdown_queue.put(True)
            self.observer_process.join()
            self.__logger.debug("observer shutdown")

            # Tell merger to shut down
            self.resqueue.put(SHUTDOWN_SENTINEL)
            self.merger_thread.join()
            self.__logger.debug("merger shutdown")

            #Tell packet sender to shut down    #doesn't work because of the observer and i merger cant be shutdown before merger
            self.ipqueue.put(SHUTDOWN_SENTINEL)
            self.packet_sender_process.join()
            self.__logger.debug("sender shutdown")

            self.traceoutqueue.join()

            # Wait for merged results to be written
            self.outqueue.join()
            self.__logger.debug("all results retrieved")
            
            
            self.traceoutqueue.put(SHUTDOWN_SENTINEL)
            
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
