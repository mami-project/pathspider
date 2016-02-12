import collections
import threading
import logging
import mplane
import pandas as pd
import numpy as np
import time


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

EcnJob = collections.namedtuple('EcnJob', ['chunk_id', 'addrs', 'ipv', 'when', 'flavor', 'token'])

class EcnImp:
    def __init__(self, name, tls_state, url, result_sink):
        self.name = name
        self.queued = collections.deque()
        self.pending_token = None
        self.pending = None
        self.result_sink = result_sink

        self.url = url
        self.client = mplane.client.HttpInitiatorClient(tls_state = tls_state)

        self.paused = False
        self.running = True
        self.last_exception = None
        self.worker_thread = threading.Thread(target=self.worker, name='EcnImp-'+self.name, daemon=True)
        self.worker_thread.start()

    def pause(self):
        logger = logging.getLogger('ecnclient.imp-'+self.name)
        logger.info("paused.")
        self.paused = True

    def resume(self):
        logger = logging.getLogger('ecnclient.imp-'+self.name)
        logger.info("resumed.")
        self.paused = False

    def shutdown(self):
        logger = logging.getLogger('ecnclient.imp-'+self.name)
        logger.info("Attempting shutdown...")
        self.running = False

        # interrupt running operations
        if self.pending_token is not None:
            logger.info("Interrupting measurement '{}'".format(self.pending_token))
            self.client.interrupt_capability(self.pending_token)
            self.pending_token = None
            self.pending = None
        logger.info("Shutdown completed")

    def is_busy(self):
        return len(self.queued) > 0 or self.pending is not None

    def worker(self):
        logger = logging.getLogger('ecnclient.imp-'+self.name)
        logger.info("Getting capabilities from {}".format(self.url))
        self.client.retrieve_capabilities(self.url)
        logger.info("Started.")
        while self.running:
            try:
                if not self.paused and self.pending_token is None and len(self.queued) > 0:
                    self.pending = self.queued.popleft()
                    label = None
                    params = None
                    try:
                        if self.pending.flavor == 'tcp':
                            label = 'ecnspider-'+self.pending.ipv
                            params = { "destination."+self.pending.ipv: [str(addr[0]) for addr in self.pending.addrs],
                                       "destination.port": [int(addr[1]) for addr in self.pending.addrs]}
                        elif self.pending.flavor == 'http':
                            label = 'ecnspider-http-'+self.pending.ipv
                            params = { "destination."+self.pending.ipv: [str(addr[0]) for addr in self.pending.addrs],
                                       "destination.port": [int(addr[1]) for addr in self.pending.addrs],
                                       "ecnspider.hostname": [addr[2] for addr in self.pending.addrs]}

                        if label is None or params is None:
                            raise ValueError("imp-{}: ecnspider flavor {} is not supported by me.".format(self.name, self.pending.flavor))

                        logger.info("Invoking measurement {} of chunk {} (containing {} addresses)".format(label, self.pending.chunk_id, len(self.pending.addrs)))
                        spec = self.client.invoke_capability(label, self.pending.when, params)
                        self.pending_token = spec.get_token()
                    except KeyError as e:
                        logger.exception("Specified URL does not support '{}' capability.".format(label))

                    if self.pending_token is None:
                        logger.error("Could not acquire request token.")
                        self.result_sink(self.name, None, self.pending.chunk_id)
                        self.pending = None

                    # wait some time
                    time.sleep(2)

                elif self.pending_token is not None:
                    try:
                        self.client.retrieve_capabilities(self.url)
                    except:
                        logger.exception("URL '{}' is unreachable. Retrying in 5 seconds.".format(str(self.url)))

                    # check results
                    result = self.client.result_for(self.pending_token)
                    if isinstance(result, mplane.model.Exception):
                        # upon exception, add to queued again.
                        logger.error(result.__repr__())
                        #TODO: mplane doesn't like to forget exceptions??
                        #self.client.forget(self.pending_token)
                        self.queued.appendleft(self.pending)
                        self.pending_token = None
                        self.pending = None
                    elif isinstance(result, mplane.model.Receipt):
                        # still ongoing.. wait for a moment
                        time.sleep(10)
                    elif isinstance(result, mplane.model.Result):
                        # add to results
                        self.client.forget(self.pending_token)
                        result_list = list(result.schema_dict_iterator())
                        self.result_sink(self.name, result_list, self.pending.chunk_id)
                        logger.info("Result for chunk id: {} ({} result rows)".format(self.pending.chunk_id, len(result_list)))
                        self.pending_token = None
                        self.pending = None
                    else:
                        # other result, just print it out
                        logger.warn(str(result))
                        time.sleep(10)
            except Exception as e:
                self.last_exception = e
                logger.exception("Error handling ecn component.")
            time.sleep(0.5)

    def add_job(self, addrs, chunk_id, ipv, flavor):
        job = EcnJob(chunk_id, addrs, ipv, "now ... future", flavor, None)
        self.queued.append(job)


class EcnAnalysis:
    def __init__(self, compiled_chunk=None, ipv='ip4', sites=[]):
        self.chunks = []

        # FIXME make these actual empty dataframes with columns...
        self.offline = pd.DataFrame()
        self.always_works = pd.DataFrame()
        self.always_broken = pd.DataFrame()
        self.works_per_site = pd.DataFrame()
        self.other = pd.DataFrame()
        self.incomplete = []

        self.sites = sites

        if compiled_chunk is not None:
            self._analyze(compiled_chunk, ipv)

    def get_ip_and_result(self):
        for ip, result in self.offline.iterrows():
            yield (ip, 'offline', result)

        for ip, result in self.always_works.iterrows():
            yield (ip, 'safe', result)

        for ip, result in self.always_broken.iterrows():
            yield (ip, 'broken_path', result)

        for ip, result in self.works_per_site.iterrows():
            yield (ip, 'broken_site', result)

        for ip, result in self.other.iterrows():
            yield (ip, 'broken_other', result)

    def __add__(self, other):
        if not isinstance(other, EcnAnalysis):
            raise NotImplementedError("Only instances of Analysis can be added here.")
        newa = EcnAnalysis(None, sites=self.sites)

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

        merged_site_columns = {}
        for site in self.sites:
            merged_site_columns[site+":conn"] = RESULT_NOBODYHOME
            merged_site_columns[site+":nego"] = RESULT_NOBODYHOME

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
                    merged[ip] = merged_site_columns.copy()
                    merged[ip]['destination.'+ipv] = ip
                    merged[ip]['destination.port'] = ecn_off['destination.port']

                merged[ip][site+':conn'] = conn
                merged[ip][site+':nego'] = nego

        #TODO: if a site does not contribute any results, the corresponding columns are missing.
        #TODO: this happens only if the amount of IPs is very low.

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

class EcnClient:
    def __init__(self, result_sink, tls_state, probes, ipv='ip4'):
        self.ipv = ipv
        self.imps = [EcnImp(name, tls_state, url, self.imp_sink) for name, url in probes]
        self.sites = [name for name, url in probes]

        self.imps_results_lock = threading.RLock()
        self.imps_results = {name: {} for name, _ in probes}

        self.result_sink = result_sink

        self.running = True
        self.thread = threading.Thread(target=self.analyzer_func, daemon=True, name="ecnclient")
        self.thread.start()

    def add_job(self, addrs, chunk_id, ipv, flavor):
        for imp in self.imps:
            imp.add_job(addrs, chunk_id, ipv, flavor)

    def pause(self):
        for imp in self.imps:
            imp.pause()

    def resume(self):
        for imp in self.imps:
            imp.resume()

    def shutdown(self):
        logger = logging.getLogger('ecnclient')
        logger.info("Attempting shutdown...")
        self.running = False
        for imp in self.imps:
            imp.shutdown()

        logger.info("Shutdown complete.")

    def imp_sink(self, name, result, chunk_id):
        with self.imps_results_lock:
            self.imps_results[name][chunk_id] = result

    def analyzer_func(self):
        logger = logging.getLogger('ecnclient')
        logger.info("Analyzer started.")

        while self.running:
            # determine chunks which have been completed by all probes
            chunks_finished = None
            with self.imps_results_lock:
                for name, results in self.imps_results.items():
                    if len(results) > 0:
                        logger.debug("{} finished chunks: {}".format(name, ",".join([str(chunk_id) for chunk_id in results.keys()])))

                    if chunks_finished is None:
                        chunks_finished = set(results.keys())
                    else:
                        chunks_finished &= set(results.keys())

            if len(chunks_finished) == 0:
                time.sleep(1)
                continue

            logger.info("Measurement for chunks {} now completed by all probes.".format(",".join([str(chunk_id) for chunk_id in chunks_finished])))

            for chunk_id in chunks_finished:
                # pop chunks finished by all probes from imp results pool
                compiled_chunk = {}
                with self.imps_results_lock:
                    for name, results in self.imps_results.items():
                        compiled_chunk[name] = pd.DataFrame(results.pop(chunk_id))

                logger.debug("processing chunk {}".format(chunk_id))
                analysis = EcnAnalysis(compiled_chunk, self.ipv, sites=self.sites)
                logger.debug("calling result_sink() with result of chunk {}...".format(chunk_id))
                self.result_sink(analysis, chunk_id)
                logger.debug("result_sink() returned.")

        logger.info("Analyzer complete.")

    def is_busy(self):
        return any(imp.is_busy() for imp in self.imps)

    def status(self):
        stat = []
        for imp in self.imps:
            with self.imps_results_lock:
                finished = list(self.imps_results[imp.name].keys())

            stat.append({
                'name': imp.name,
                'queued': [job.chunk_id for job in imp.queued],
                'finished': finished,
                'pending': imp.pending[0] if imp.pending is not None else None,
                'running': imp.running,
                'paused': imp.paused,
                'last_exception': repr(imp.last_exception) if imp.last_exception is not None else None
            })

        return stat
