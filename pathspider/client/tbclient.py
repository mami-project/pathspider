import collections
import mplane
import mplane.client
import threading
import logging
import time
from ipaddress import ip_address
import pandas as pd

TbJob = collections.namedtuple('TbJob', ['ip', 'port', 'ipv', 'probe', 'when'])

class TbImp:
    def __init__(self, name, tls_state, url):
        self.name = name
        self.url = url
        self.client = mplane.client.HttpInitiatorClient({}, tls_state)
        self.queued = collections.deque()
        self.pending_token = None
        self.pending = None
        self.finished = {}

        self.paused = False
        self.running = True

        self.last_exception = None

        self.lock = threading.RLock()
        self.worker_thread = threading.Thread(target=self.worker, name='TraceboxImp-'+self.name, daemon=True)
        self.worker_thread.start()

    def pause(self):
        logger = logging.getLogger('tbclient.imp-'+self.name)
        logger.info("paused.")
        self.paused = True

    def resume(self):
        logger = logging.getLogger('tbclient.imp-'+self.name)
        logger.info("resumed.")
        self.paused = False

    def shutdown(self):
        logger = logging.getLogger('tbclient.imp-'+self.name)
        logger.info("Attempting shutdown...")
        with self.lock:
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
        logger = logging.getLogger('tbclient.imp-'+self.name)
        logger.info("Getting capabilities from {}".format(self.url))
        self.client.retrieve_capabilities(self.url)
        logger.info("Started.")
        while self.running:
            try:
                with self.lock:
                    if not self.paused and self.pending_token is None and len(self.queued) > 0:
                        logger.info("Sending tracebox request.")
                        self.pending = self.queued.popleft()
                        label = 'scamper-tracebox-specific-'+self.pending.ipv
                        try:
                            spec = self.client.invoke_capability(label, self.pending.when,
                                                                 { 'destination.'+self.pending.ipv: self.pending.ip, 'scamper.tracebox.dport': self.pending.port, 'scamper.tracebox.probe': self.pending.probe } )
                            self.pending_token = spec.get_token()
                        except KeyError:
                            logger.exception("Specified URL does not support '{}' capability.".format(label))

                        if self.pending_token is None:
                            logger.exception("Could not acquire request token.")
                            self.finished[self.pending.url] = None
                            self.pending = None

                        continue
                    elif self.pending_token is not None:
                        try:
                            self.client.retrieve_capabilities(self.url)
                        except:
                            logger.exception("URL '{}' unreachable. Retrying in 5 seconds".format(str(self.url)))

                        # check results
                        result = self.client.result_for(self.pending_token)
                        if isinstance(result, mplane.model.Exception):
                            # upon exception, add to queued again.
                            logger.error(result.__repr__())
                            #self.client.forget(self.pending_token)
                            self.queued.append(self.pending)
                            self.pending_token = None
                            self.pending = None
                        elif isinstance(result, mplane.model.Receipt):
                            # still ongoing.. wait for a moment
                            time.sleep(10)
                        elif isinstance(result, mplane.model.Result):
                            logger.info("Got trace for IP {}.".format(self.pending.ip))
                            # add to results
                            self.client.forget(self.pending_token)
                            self.finished[self.pending.ip] = list(result.schema_dict_iterator())
                            self.pending_token = None
                            self.pending = None
                        else:
                            # other result, just print it out
                            logger.warn(result)
                            time.sleep(10)
            except Exception as e:
                self.last_exception = e
                logger.exception("Error handling tracebox component.")
            time.sleep(0.5)

    def add_job(self, ip, port, mode='tcp'):
        if mode == 'tcp':
            probe = 'IP/TCP/ECE'
        else:
            raise NotImplementedError("This mode is not implemented.")

        self.queued.append(TbJob(ip, port, 'ip'+str(ip_address(ip).version), probe, 'now ... future'))


class TbClient:
    def __init__(self, result_sink, tls_state, probes, ipv='ip4'):
        self.ipv = ipv
        self.imps = [TbImp(name, tls_state, url) for name, url in probes]

        self.result_sink = result_sink

        self.paused = False
        self.running = True
        self.thread = threading.Thread(target=self.trackdown_func, daemon=True, name="tbclient")
        self.thread.start()

    def add_job(self, ip, port, mode='tcp'):
        for imp in self.imps:
            imp.add_job(ip, port, mode)

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

    def trackdown_func(self):
        logger = logging.getLogger('tbclient')
        logger.info("Started.")

        while self.running:
            chunks_finished = None
            for imp in self.imps:
                with imp.lock:
                    if len(imp.finished) > 0:
                        logger.info("{} finished chunks: {}".format(imp.name, ",".join([str(chunk_id) for chunk_id in imp.finished.keys()]), len(imp.queued)))

                    if chunks_finished is None:
                        chunks_finished = set(imp.finished.keys())
                    else:
                        chunks_finished &= set(imp.finished.keys())

            if len(chunks_finished) == 0:
                time.sleep(1)
                continue

            logger.info("Measurement for chunks {} now completed by all probes.".format(",".join([str(chunk_id) for chunk_id in chunks_finished])))

            for ip in chunks_finished:
                compiled_chunk = {}
                for imp in self.imps:
                    with imp.lock:
                        compiled_chunk[imp.name] = pd.DataFrame(imp.finished.pop(ip))

                logger.info("processing trace of ip {}".format(ip))

                graph = {}
                for name, chunk in compiled_chunk.items():
                    if len(chunk) > 0:
                        graph[name] = list(chunk['scamper.tracebox.hop.'+self.ipv])
                    else:
                        graph[name] = []

                self.result_sink(ip, graph)
                logger.debug("result_sink() returned.")

    def is_busy(self):
        return any(imp.is_busy() for imp in self.imps)

    def status(self):
        stat = []
        for imp in self.imps:
            stat.append({
                'name': imp.name,
                'queued': [str(job.ip) for job in imp.queued],
                'finished': [str(ip) for ip in imp.finished],
                'pending': imp.pending.ip if imp.pending is not None else None,
                'running': imp.running,
                'paused': imp.paused,
                'last_exception': repr(imp.last_exception)
            })

        return stat