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

QUEUE_SLEEP = 0.5

class NotFinishedException(Exception):
    pass

class EcnSpiderImp:
    QUEUED_MIN_LENGTH = 2

    ChunkJob = collections.namedtuple('ChunkJob', ['chunk_id', 'addrs', 'ipv', 'when', 'flavor', 'token'])

    def __init__(self, name, tls_state, url):
        self.name = name
        self.queued = collections.deque()
        self.pending_token = None
        self.pending = None
        self.finished = {}

        self.url = url
        self.client = mplane.client.HttpInitiatorClient(tls_state)
        self.client.retrieve_capabilities(self.url)

        self.lock = threading.RLock()
        self.worker_thread = threading.Thread(target=self.worker, name='EcnSpiderImp-'+self.name, daemon=True)
        self.worker_thread.start()

    def worker(self):
        print("imp-{}: started".format(self.name))
        while True:
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
            self.queued.append(EcnSpiderImp.ChunkJob(chunk_id, addrs, ipv, when, flavor, None))

class TraceboxImp:
    TraceboxJob = collections.namedtuple('TraceboxJob', ['ip', 'port', 'ipv', 'probe', 'when'])

    def __init__(self, name, tls_state, url):
        self.name = name
        self.url = url
        self.client = mplane.client.HttpInitiatorClient(tls_state)
        self.client.retrieve_capabilities(self.url)
        self.queued = collections.deque()
        self.pending_token = None
        self.pending = None
        self.finished = {}

        self.lock = threading.RLock()
        self.worker_thread = threading.Thread(target=self.worker, name='TraceboxImp-'+self.name, daemon=True)
        self.worker_thread.start()

    def worker(self):
        while True:
            with self.lock:
                if self.pending_token is None and len(self.queued) > 0:
                    print("sending tracebox request")
                    self.pending = self.queued.popleft()
                    label = 'scamper-tracebox-specific-'+self.pending.ipv
                    try:
                        spec = self.client.invoke_capability(label, self.pending.when,
                                                             { 'destination.'+self.pending.ipv: self.pending.ip, 'scamper.tracebox.dport': self.pending.port, 'scamper.tracebox.probe': self.pending.probe } )
                        self.pending_token = spec.get_token()
                    except KeyError as e:
                        print("Specified URL does not support '"+label+"' capability.")

                    if self.pending_token is None:
                        print("Could not acquire request token.")
                        self.finished[self.pending.url] = None
                        self.pending = None

                    continue
                elif self.pending_token is not None:
                    try:
                        self.client.retrieve_capabilities(self.url)
                    except:
                        print(str(self.url) + " unreachable. Retrying in 5 seconds")

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
                        print("received result for: ", self.pending.ip)
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

        self.queued.append(TraceboxImp.TraceboxJob(ip, port, 'ip'+str(ip_address(ip).version), probe, when))

class PathSpiderClient:
    # queued chunks - in queue to be sent to ecnspider component, feeder thread loads addresses
    # pending chunks - currently processing
    # finished chunks - finished, interrupted chunks or chunks which encountered an exception, consumer thread takes finished chunks and do further investigation

    AnalysisResult = collections.namedtuple('AnalysisResult', ['offline', 'always_works', 'always_broken', 'works_per_site', 'other'])

    def __init__(self, count, tls_state, ecnspiders_name_and_urls, resolver, chunk_size = 1000, ipv='ip4'):
        self.chunk_size = chunk_size
        self.ipv = ipv
        self.imps = [EcnSpiderImp(name, tls_state, url) for name, url in ecnspiders_name_and_urls]

        self.lock = threading.RLock()

        self.resolver_thread = threading.Thread(target=self.resolver_func, daemon=True, name="resolver")
        self.analyzer_thread = threading.Thread(target=self.analyzer_func, daemon=True, name="analyzer")
        self.trackdown_thread = threading.Thread(target=self.trackdown_func, daemon=True, name="trackdown")

        self.resolver = resolver
        self.resolver_thread.start()
        self.analyzer_thread.start()
        self.trackdown_thread.start()

    def resolver_func(self):
        print("resolver: started")
        next_chunk_id = 0
        while True:
            if any([imp.need_chunk() for imp in self.imps]):
                print("resolver: requesting {} addresses from resolver. This may take some time.".format(self.chunk_size))
                try:
                    addrs = self.resolver.request(self.chunk_size, ipv=self.ipv)
                except resolver.TimeoutException as e:
                    print("resolver: got a timeout on resolving. try later...")
                    time.sleep(5)
                    continue

                if len(addrs) == 0:
                    print("resolver: resolver has no more addresses.")
                    break

                print("resolver: received {} addresses. adding to ecnspiders".format(len(addrs)))
                for imp in self.imps:
                    imp.add_chunk(addrs, next_chunk_id, self.ipv, "now ... future", self.resolver.flavor)

                next_chunk_id += 1

            time.sleep(QUEUE_SLEEP)

    def analyzer_func(self):
        print("analyzer started")

        statistics = {}
        while True:
            chunks_finished = None
            for imp in self.imps:
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
                for imp in self.imps:
                    with imp.lock:
                        compiled_chunk[imp.name] = pd.DataFrame(imp.finished.pop(chunk_id))

                print("analyzer: processing chunk {}".format(chunk_id))
                statistics[chunk_id] = self.analyzer_process_chunk(compiled_chunk)

    def analyzer_process_chunk(self, compiled_chunk):
        #
        # first analyze each vantage point separately
        incomplete = {}
        merged_results = {}
        sites = []
        for site, chunk in compiled_chunk.items():
            sites.append(site)
            for ip, result in chunk.groupby('destination.'+self.ipv):
                if result.shape[0] != 2:
                    if site not in incomplete:
                        incomplete[site] = {}
                    incomplete[site][ip] = result
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

                if ip not in merged_results:
                    merged_results[ip] = {'destination.'+self.ipv: ip, 'destination.port': ecn_off['destination.port']}

                merged_results[ip][site+':conn'] = conn
                merged_results[ip][site+':nego'] = nego

        # convert to dataframe
        merged_results = pd.DataFrame(merged_results).T
        sites = pd.Series(sites)

        for site, incom in incomplete.items():
            print("analyzer: number incomplete measurements from {} = {}".format(site, len(incom)))

        if merged_results.shape[1] == 0:
            print("analyzer: no usable results in this chunk.")
            return PathSpiderClient.AnalysisResult(None, None, None, None, None)

        # # # # # # # # # # # # # # # # # # # # # # # # #
        # offline: never made any successful connection #
        mask_offline = merged_results[sites+':conn'].apply(lambda x: x == RESULT_NOBODYHOME, reduce=False).all(axis=1)
        df_online = merged_results[-mask_offline]
        df_offline = merged_results[mask_offline]

        num_offline = (mask_offline.sum())
        num_online = (-mask_offline).sum()
        print("analyzer: online: {} ({:.2%})".format(num_online, num_online/merged_results.shape[0]))

        if num_online == 0:
            print("analyzer: no further analysis possible, because all hosts offline.")
            return PathSpiderClient.AnalysisResult(df_offline, None, None, None, None)

        # # # # # # # # # # # # # # # # # # # # #
        # always works without ECN and with ECN #
        mask_works = df_online[sites+':conn'].apply(lambda x: x == RESULT_WORKS, reduce=False).all(axis=1)
        df_works = df_online[mask_works]
        num_works = mask_works.sum()

        print("analyzer: works all path: {} ({:.3%})".format(num_works, num_works/num_online))

        # gather the rest
        num_works_not = (np.logical_not(mask_works)).sum()
        df_works_not = df_online[np.logical_not(mask_works)]

        # # # # # # # # # # # # # # # # # # # # # # # #
        # always works without ECN but never with ECN #
        mask_totally_broken = df_works_not[sites+':conn'].apply(lambda x: x == RESULT_BROKEN, reduce=False).all(axis=1)
        df_totally_broken = df_works_not[mask_totally_broken]
        num_totally_broken = mask_totally_broken.sum()

        print("analyzer: always works without ECN but never with ECN: {} ({:.3%})".format(num_totally_broken, num_totally_broken/num_online))

        # gather the rest
        num_totally_broken_not = (np.logical_not(mask_totally_broken)).sum()
        df_totally_broken_not = df_works_not[np.logical_not(mask_totally_broken)]

        # # # # # # # # # # # # # # # # # # # # # # # # # #
        # either works with and without ECN or not at all #
        mask_works_per_site = df_totally_broken_not[sites+':conn'].apply(lambda x: (x == RESULT_WORKS) | (x == RESULT_NOBODYHOME), reduce=False).all(axis=1)
        df_works_per_site = df_totally_broken_not[mask_works_per_site]
        num_works_per_site = mask_works_per_site.sum()
        print("analyzer: either works with and without ECN or not at all: {} ({:.3%})".format(num_works_per_site, num_works_per_site/num_online))

        # gather the rest
        num_works_per_site_not = (np.logical_not(mask_works_per_site)).sum()
        df_works_per_site_not = df_totally_broken_not[np.logical_not(mask_works_per_site)]

        print("analyzer: transient/other: {} ({:.3%})".format(num_works_per_site_not, num_works_per_site_not/num_online))

        return PathSpiderClient.AnalysisResult(df_offline, df_works, df_totally_broken, df_works_per_site, df_works_per_site_not)

    def trackdown_func(self):
        print("trackdown: started")
        while True:
            time.sleep(QUEUE_SLEEP)
