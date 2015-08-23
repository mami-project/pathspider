"""
Ecnspider2: Qofspider-based tool for measuring ECN-linked connectivity
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

.. moduleauthor:: Elio Gubser <elio.gubser@alumni.ethz.ch>

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

import mplane
import mplane.tls
import mplane.utils
import mplane.client
import time
import collections
import threading
import itertools
import numpy as np
import pandas as pd
from ipaddress import ip_address
from . import resolver

# Flags constants
TCP_CWR = 0x80
TCP_ECE = 0x40
TCP_URG = 0x20
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_RST = 0x04
TCP_SYN = 0x02
TCP_FIN = 0x01

# QoF TCP Characteristics constants
QOF_ECT0 =    0x01
QOF_ECT1 =    0x02
QOF_CE   =    0x04
QOF_TSOPT =   0x10
QOF_SACKOPT = 0x20
QOF_WSOPT =   0x40

SAE = (TCP_SYN | TCP_ECE | TCP_ACK)
SAEW = (TCP_SYN | TCP_ECE | TCP_ACK | TCP_CWR)

RESULT_NOBODYHOME = 0
RESULT_OTHER = 1
RESULT_BROKEN = 2
RESULT_WORKS = 3

QUEUE_SLEEP = 2

class NotFinishedException(Exception):
    pass

class EcnSpiderImp:
    QUEUED_MIN_LENGTH = 2

    Job = collections.namedtuple('ChunkJob', ['chunk_id', 'addrs', 'ipv', 'when', 'flavor', 'token'])

    def __init__(self, name, tls_state, url):
        self.name = name
        self.queued = collections.deque()
        self.pending_token = None
        self.pending = None
        self.finished = {}

        self.url = url
        self.client = mplane.client.HttpInitiatorClient({}, tls_state)
        self.client.retrieve_capabilities(self.url)

        self.lock = threading.RLock()
        self.running = True
        self.worker_thread = threading.Thread(target=self.worker, name='EcnSpiderImp-'+self.name, daemon=True)
        self.worker_thread.start()

    def shutdown(self):
        print("imp-{}: Attempting shutdown...".format(self.name))
        with self.lock:
            self.running = False

            # interrupt running operations
            if self.pending_token is not None:
                print("imp-{}: Interrupting measurement '{}'".format(self.name, self.pending_token))
                self.client.interrupt_capability(self.pending_token)
                self.pending_token = None
                self.pending = None
        print("imp-{}: Shutdown completed".format(self.name))

    def has_work(self):
        return len(self.queued) > 0 or self.pending is not None

    def worker(self):
        print("imp-{}: started".format(self.name))
        while self.running:
            with self.lock:
                if self.pending_token is None and len(self.queued) > 0:
                    self.pending = self.queued.popleft()
                    label = None
                    params = None
                    try:
                        if self.pending.flavor == 'tcp':
                            label = 'ecnspider-'+self.pending.ipv
                            params = { "destination."+self.pending.ipv: [str(addr.ip) for addr in self.pending.addrs],
                                       "destination.port": [int(addr.port) for addr in self.pending.addrs]}
                        elif self.pending.flavor == 'http':
                            label = 'ecnspider-http-'+self.pending.ipv
                            params = { "destination."+self.pending.ipv: [str(addr.ip) for addr in self.pending.addrs],
                                       "destination.port": [int(addr.port) for addr in self.pending.addrs],
                                       "ecnspider.hostname": [addr.hostname for addr in self.pending.addrs]}

                        if label is None or params is None:
                            raise ValueError("imp-{}: ecnspider flavor {} is not supported by me.".format(self.name, self.pending.flavor))

                        print("imp-{}: invoking measurement {} of chunk {} (containing {} addresses)".format(self.name, label, self.pending.chunk_id, len(self.pending.addrs)))
                        spec = self.client.invoke_capability(label, self.pending.when, params)
                        self.pending_token = spec.get_token()
                    except KeyError as e:
                        print("imp-{}: Specified URL does not support '{}' capability.".format(self.name, label), e)

                    if self.pending_token is None:
                        print("imp-{}: Could not acquire request token.".format(self.name))
                        self.finished[self.pending.chunk_id] = None
                        self.pending = None

                elif self.pending_token is not None:
                    try:
                        self.client.retrieve_capabilities(self.url)
                    except:
                        print("imp-{}: {} unreachable. Retrying in 5 seconds".format(self.name, str(self.url)))

                    # check results
                    result = self.client.result_for(self.pending_token)
                    if isinstance(result, mplane.model.Exception):
                        # upon exception, add to queued again.
                        print("imp-{}: ".format(self.name) + result.__repr__())
                        #TODO: mplane doesn't like to forget exceptions??
                        #self.client.forget(self.pending_token)
                        self.queued.append(self.pending)
                        self.pending_token = None
                        self.pending = None
                    elif isinstance(result, mplane.model.Receipt):
                        pass
                    elif isinstance(result, mplane.model.Result):
                        # add to results
                        self.client.forget(self.pending_token)
                        self.finished[self.pending.chunk_id] = list(result.schema_dict_iterator())
                        print("imp-{}: received result for chunk id: {} ({} result rows)".format(self.name, self.pending.chunk_id, len(self.finished[self.pending.chunk_id])))
                        self.pending_token = None
                        self.pending = None
                    else:
                        # other result, just print it out
                        print("imp-{}".format(self.name), result)

            time.sleep(2.5)

    def need_chunk(self):
        with self.lock:
            return len(self.queued) < EcnSpiderImp.QUEUED_MIN_LENGTH

    def add_chunk(self, addrs, chunk_id, ipv, when, flavor):
        with self.lock:
            self.queued.append(EcnSpiderImp.Job(chunk_id, addrs, ipv, when, flavor, None))

class TraceboxImp:
    Job = collections.namedtuple('TraceboxJob', ['ip', 'port', 'ipv', 'probe', 'when'])

    def __init__(self, name, tls_state, url):
        self.name = name
        self.url = url
        self.client = mplane.client.HttpInitiatorClient({}, tls_state)
        self.client.retrieve_capabilities(self.url)
        self.queued = collections.deque()
        self.pending_token = None
        self.pending = None
        self.finished = {}

        self.lock = threading.RLock()
        self.worker_thread = threading.Thread(target=self.worker, name='TraceboxImp-'+self.name, daemon=True)
        self.worker_thread.start()

    def shutdown(self):
        print("tbimp-{}: Attempting shutdown...".format(self.name))
        with self.lock:
            self.running = False

            # interrupt running operations
            if self.pending_token is not None:
                print("tbimp-{}: Interrupting measurement '{}'".format(self.name, self.pending_token))
                self.client.interrupt_capability(self.pending_token)
                self.pending_token = None
                self.pending = None
        print("tbimp-{}: Shutdown completed".format(self.name))

    def has_work(self):
        return len(self.queued) > 0 or self.pending is not None

    def worker(self):
        while True:
            with self.lock:
                if self.pending_token is None and len(self.queued) > 0:
                    print("tbimp-{}: sending tracebox request".format(self.name))
                    self.pending = self.queued.popleft()
                    label = 'scamper-tracebox-specific-'+self.pending.ipv
                    try:
                        spec = self.client.invoke_capability(label, self.pending.when,
                                                             { 'destination.'+self.pending.ipv: self.pending.ip, 'scamper.tracebox.dport': self.pending.port, 'scamper.tracebox.probe': self.pending.probe } )
                        self.pending_token = spec.get_token()
                    except KeyError as e:
                        print("tbimp-{}: tracebox-imp: Specified URL does not support '{}' capability.".format(self.name, label))

                    if self.pending_token is None:
                        print("tbimp-{}: tracebox-imp: Could not acquire request token.".format(self.name))
                        self.finished[self.pending.url] = None
                        self.pending = None

                    continue
                elif self.pending_token is not None:
                    try:
                        self.client.retrieve_capabilities(self.url)
                    except:
                        print("tbimp-{}: {} unreachable. Retrying in 5 seconds".format(self.name, str(self.url)))

                    # check results
                    result = self.client.result_for(self.pending_token)
                    if isinstance(result, mplane.model.Exception):
                        # upon exception, add to queued again.
                        print(result.__repr__())
                        self.client.forget(self.pending_token)
                        self.queued.append(self.pending)
                        self.pending_token = None
                        self.pending = None
                    elif isinstance(result, mplane.model.Receipt):
                        pass
                    elif isinstance(result, mplane.model.Result):
                        print("tbimp-{}: received result for: {} ".format(self.name, self.pending.ip))
                        # add to results
                        self.client.forget(self.pending_token)
                        self.finished[self.pending.ip] = list(result.schema_dict_iterator())
                        self.pending_token = None
                        self.pending = None
                    else:
                        # other result, just print it out
                        print(result)

            time.sleep(QUEUE_SLEEP)

    def add(self, ip, port, when='now ... future', mode='tcp'):
        if mode == 'tcp':
            probe = 'IP/TCP/ECE'
        else:
            raise NotImplementedError("This mode is not implemented.")

        self.queued.append(TraceboxImp.Job(ip, port, 'ip'+str(ip_address(ip).version), probe, when))

class EcnAnalysis:
    def __init__(self, compiled_chunk, ipv='ip4'):
        self.chunks = []
        self.offline = pd.DataFrame()
        self.always_works = pd.DataFrame()
        self.always_broken = pd.DataFrame()
        self.works_per_site = pd.DataFrame()
        self.other = pd.DataFrame()
        self.incomplete = []

        if compiled_chunk is not None:
            self._analyze(compiled_chunk, ipv)

    def __add__(self, other):
        if not isinstance(other, EcnAnalysis):
            raise NotImplementedError("Only instances of Analysis can be added here.")
        newa = EcnAnalysis(None)

        newa.chunks = self.chunks + other.chunks
        newa.offline = self.offline.append(other.offline)
        newa.always_works = self.always_works.append(other.always_works)
        newa.always_broken = self.always_broken.append(other.always_broken)
        newa.works_per_site = self.works_per_site.append(other.works_per_site)
        newa.other = self.other.append(other.other)
        newa.incomplete = self.incomplete + other.incomplete

        return newa

    def to_json(self):
        return {'offline': len(self.offline),
                'online': len(self),
                'always_works': len(self.always_works),
                'always_broken': len(self.always_broken),
                'works_per_site': len(self.works_per_site),
                'other': len(self.other)}

    def dump(self):
        num_online = len(self)
        print("online: {} ({:.2%})".format(num_online, num_online/(num_online+len(self.offline))))

        if num_online == 0:
            return

        print("analyzer: works all path: {} ({:.3%})".format(len(self.always_works), len(self.always_works)/num_online))

        print("analyzer: always works without ECN but never with ECN: {} ({:.3%})".format(len(self.always_broken), len(self.always_broken)/num_online))

        print("analyzer: either works with and without ECN or not at all: {} ({:.3%})".format(len(self.works_per_site), len(self.works_per_site)/num_online))

        print("analyzer: transient/other: {} ({:.3%})".format(len(self.other), len(self.other)/num_online))

    def __len__(self):
        """
        :return: the number of successful measurements
        """
        return len(self.always_works) + len(self.always_broken) + len(self.works_per_site) + len(self.other)

    def _merge_results(self, compiled_chunk, ipv):
        merged = {}
        incomplete = []
        for site, chunk in compiled_chunk.items():
            for ip, result in chunk.groupby('destination.'+ipv):
                if result.shape[0] != 2:
                    incomplete.append((site, ip, result))
                    continue

                if result.iloc[0]['ecnspider.ecnstate'] == 1:
                    ecn_on = result.iloc[0]
                    ecn_off = result.iloc[1]
                else:
                    ecn_off = result.iloc[0]
                    ecn_on = result.iloc[1]

                nego = (ecn_on['ecnspider.synflags.rev'] & SAEW) == SAE

                if ecn_off['connectivity.ip'] and ecn_on['connectivity.ip']:
                    conn = RESULT_WORKS
                elif ecn_off['connectivity.ip'] and not ecn_on['connectivity.ip']:
                    conn = RESULT_BROKEN
                elif not ecn_off['connectivity.ip'] and not ecn_on['connectivity.ip']:
                    conn = RESULT_NOBODYHOME
                else:
                    conn = RESULT_OTHER

                if ip not in merged:
                    merged[ip] = {'destination.'+ipv: ip, 'destination.port': ecn_off['destination.port']}

                merged[ip][site+':conn'] = conn
                merged[ip][site+':nego'] = nego

        # convert to dataframe
        merged = pd.DataFrame(merged).T
        return merged, incomplete

    def _analyze(self, compiled_chunk, ipv='ip4'):
        self.chunks.append(compiled_chunk)

        merged, self.incomplete = self._merge_results(compiled_chunk, ipv)
        sites = pd.Series([str(key) for key in compiled_chunk.keys()])

        print("analyzer: number incomplete measurements: {}".format(len(self.incomplete)))

        if len(merged) == 0:
            print("analyzer: no usable results in this chunk.")
            return

        # # # # # # # # # # # # # # # # # # # # # # # # #
        # offline: never made any successful connection #
        mask_offline = merged[sites+':conn'].apply(lambda x: x == RESULT_NOBODYHOME, reduce=False).all(axis=1)
        df_online = merged[-mask_offline]
        self.offline = merged[mask_offline]

        num_offline = (mask_offline.sum())
        num_online = (-mask_offline).sum()
        print("analyzer: online: {} ({:.2%})".format(num_online, num_online/len(merged)))

        if num_online == 0:
            print("analyzer: no further analysis possible, because all hosts offline.")
            return

        # # # # # # # # # # # # # # # # # # # # #
        # always works without ECN and with ECN #
        mask_works = df_online[sites+':conn'].apply(lambda x: x == RESULT_WORKS, reduce=False).all(axis=1)
        self.always_works = df_online[mask_works]
        num_works = mask_works.sum()

        print("analyzer: works all path: {} ({:.3%})".format(num_works, num_works/num_online))

        # gather the rest
        df_works_not = df_online[np.logical_not(mask_works)]

        # # # # # # # # # # # # # # # # # # # # # # # #
        # always works without ECN but never with ECN #
        mask_totally_broken = df_works_not[sites+':conn'].apply(lambda x: x == RESULT_BROKEN, reduce=False).all(axis=1)
        self.always_broken = df_works_not[mask_totally_broken]
        num_totally_broken = mask_totally_broken.sum()

        print("analyzer: always works without ECN but never with ECN: {} ({:.3%})".format(num_totally_broken, num_totally_broken/num_online))

        # gather the rest
        df_totally_broken_not = df_works_not[np.logical_not(mask_totally_broken)]

        # # # # # # # # # # # # # # # # # # # # # # # # # #
        # either works with and without ECN or not at all #
        mask_works_per_site = df_totally_broken_not[sites+':conn'].apply(lambda x: (x == RESULT_WORKS) | (x == RESULT_NOBODYHOME), reduce=False).all(axis=1)
        self.works_per_site = df_totally_broken_not[mask_works_per_site]
        num_works_per_site = mask_works_per_site.sum()
        print("analyzer: either works with and without ECN or not at all: {} ({:.3%})".format(num_works_per_site, num_works_per_site/num_online))

        # gather the rest
        num_works_per_site_not = (np.logical_not(mask_works_per_site)).sum()
        self.other = df_totally_broken_not[np.logical_not(mask_works_per_site)]

        print("analyzer: transient/other: {} ({:.3%})".format(num_works_per_site_not, num_works_per_site_not/num_online))

class TraceAnalysis:
    def __init__(self, ip, compiled_chunk, ipv='ip4'):
        self.ip = ip
        self.graph = {}
        for name, chunk in compiled_chunk.items():
            self.graph[name] = list(chunk['scamper.tracebox.hop.'+ipv])

    def to_json(self):
        return {str(self.ip): {name: [str(trace_ip) for trace_ip in trace] for name, trace in self.graph.items()}}

    def dump(self):
        print(self.graph)

class PathSpiderClient:
    # queued chunks - in queue to be sent to ecnspider component, feeder thread loads addresses
    # pending chunks - currently processing
    # finished chunks - finished, interrupted chunks or chunks which encountered an exception, consumer thread takes finished chunks and do further investigation

    def __init__(self, count, tls_state, ecnspiders_name_and_urls, resolver, chunk_size = 1000, ipv='ip4'):
        self.count = count
        self.chunk_size = chunk_size
        self.ipv = ipv
        self.ecnimps = [EcnSpiderImp(name, tls_state, url) for name, url in ecnspiders_name_and_urls]
        self.tbimps = [TraceboxImp(name, tls_state, url) for name, url in ecnspiders_name_and_urls]

        self.resolver_thread = threading.Thread(target=self.resolver_func, daemon=True, name="resolver")
        self.analyzer_thread = threading.Thread(target=self.analyzer_func, daemon=True, name="analyzer")
        self.trackdown_thread = threading.Thread(target=self.trackdown_func, daemon=True, name="trackdown")

        self.resolver = resolver

        self.resolver_dried_out = False
        self.analyzer_dried_out = False
        self.running = True
        self.resolver_thread.start()
        self.analyzer_thread.start()
        self.trackdown_thread.start()

        self.lock = threading.RLock()
        self.results = {'ecnspider': {}, 'traces': {}}

    def resolver_func(self):
        print("resolver: started")
        next_chunk_id = 0
        while self.running:
            if any([imp.need_chunk() for imp in self.ecnimps]):
                print("resolver: requesting {} addresses from resolver. This may take some time.".format(self.chunk_size))
                try:
                    addrs = self.resolver.request(self.chunk_size, ipv=self.ipv)
                except resolver.TimeoutException as e:
                    print("resolver: got a timeout on resolving. try later...")
                    time.sleep(5)
                    continue

                if len(addrs) == 0:
                    print("resolver: resolver has no more addresses.")
                    self.resolver_dried_out = True
                    break

                print("resolver: received {} addresses. adding to ecnspiders".format(len(addrs)))
                for imp in self.ecnimps:
                    imp.add_chunk(addrs, next_chunk_id, self.ipv, "now ... future", self.resolver.flavor)

                next_chunk_id += 1

            time.sleep(QUEUE_SLEEP)

    def analyzer_func(self):
        print("analyzer started")

        analysis = EcnAnalysis(None)
        while self.running and len(analysis) < self.count:
            # stop if dried out
            if all([not imp.has_work() for imp in self.ecnimps]) and self.resolver_dried_out:
                print("analyzer finished, because no more addresses available. (resolver dried out)")
                break

            chunks_finished = None
            for imp in self.ecnimps:
                with imp.lock:
                    if len(imp.finished) > 0:
                        print("analyzer: {} has finished chunks: {}".format(imp.name, ",".join([str(chunk_id) for chunk_id in imp.finished.keys()])))

                    if chunks_finished is None:
                        chunks_finished = set(imp.finished.keys())
                    else:
                        chunks_finished &= set(imp.finished.keys())

            if len(chunks_finished) == 0:
                time.sleep(QUEUE_SLEEP)
                continue

            print("analyzer: all ecnspiders have finished chunks {} now".format(",".join([str(chunk_id) for chunk_id in chunks_finished])))

            for chunk_id in chunks_finished:
                compiled_chunk = {}
                for imp in self.ecnimps:
                    with imp.lock:
                        compiled_chunk[imp.name] = pd.DataFrame(imp.finished.pop(chunk_id))

                print("analyzer: processing chunk {}".format(chunk_id))
                analyzed_chunk = EcnAnalysis(compiled_chunk, self.ipv)

                # add to measurement collection
                analyzed_chunk.dump()
                analysis += analyzed_chunk

                # add other to tracebox queue
                if len(analyzed_chunk.other) > 0:
                    print("Adding {} ips to tracebox queue".format(len(analyzed_chunk.other)))
                    for ip, port in zip(analyzed_chunk.other['destination.'+self.ipv], analyzed_chunk.other['destination.port']):
                        for imp in self.tbimps:
                            imp.add(ip, port)


            print("Collected {} results. Remaining {}.".format(len(analysis), self.count - len(analysis)))

        print("Finished! Collected {} results. Initiating shutdown...".format(len(analysis)))

        analysis.dump()

        with self.lock:
            self.results['ecnspider'] = analysis.to_json()

        for imp in self.ecnimps:
            imp.shutdown()

        self.analyzer_dried_out = True

    def trackdown_func(self):
        print("trackdown: started")

        analysis = []
        while self.running:
            # stop if dried out
            if all([not imp.has_work() for imp in self.tbimps]) and self.analyzer_dried_out:
                print("trackdown finished, because no more addresses available. (analyzer dried out)")
                break

            chunks_finished = None
            for imp in self.tbimps:
                with imp.lock:
                    if len(imp.finished) > 0:
                        print("trackdown: {} has finished chunks: {}".format(imp.name, ",".join([str(chunk_id) for chunk_id in imp.finished.keys()])))

                    if chunks_finished is None:
                        chunks_finished = set(imp.finished.keys())
                    else:
                        chunks_finished &= set(imp.finished.keys())

            if len(chunks_finished) == 0:
                time.sleep(QUEUE_SLEEP)
                continue

            print("trackdown: all traceboxes have finished chunks {} now".format(",".join([str(chunk_id) for chunk_id in chunks_finished])))

            for ip in chunks_finished:
                compiled_chunk = {}
                for imp in self.tbimps:
                    with imp.lock:
                        compiled_chunk[imp.name] = pd.DataFrame(imp.finished.pop(ip))

                print("trackdown: processing trace of ip {}".format(ip))
                analyzed_chunk = TraceAnalysis(ip, compiled_chunk, self.ipv)
                analyzed_chunk.dump()
                analysis.append(analyzed_chunk)

            print("trackdown: Collected {} results.".format(len(analysis)))

        print("trackdown: Finished! Collected {} results. Initiating shutdown...".format(len(analysis)))

        for analyzed_chunk in analysis:
            analyzed_chunk.dump()
            self.results['traces'].update(analyzed_chunk.to_json())

        for imp in self.tbimps:
            imp.shutdown()

        self.analyzer_dried_out = True
        self.running = False

