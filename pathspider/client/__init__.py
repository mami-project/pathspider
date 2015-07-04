"""
Ecnspider2: Qofspider-based tool for measuring ECN-linked connectivity
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

Simple client for collecting endpoint addresses from the BitTorrent network
and performing ECN measurements on them.

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
import mplane.supervisor
import argparse
import configparser
import time
import collections
import threading
from ipaddress import ip_address

STAGE_RESOLVER = 0x00
STAGE_ECNSPIDER = 0x01
STAGE_TRACBOX = 0x02
STAGE_ERROR = 0x03

STATUS_QUEUED = 0x00
STATUS_RUNNING = 0x01
STATUS_FINISHED = 0x02
STATUS_ERROR = 0xFF

class NotFinishedException(Exception):
    pass

class TimeoutException(Exception):
    pass

ResolverResult = collections.namedtuple('ResolverResult', ['identifier', 'ip', 'port'])

class ResolverClient:
    def __init__(self, tls_state, resolver_url):
        self.url = resolver_url
        self.client = mplane.client.HttpInitiatorClient(tls_state)
        self.client.retrieve_capabilities(self.url)
        self.last_updated = 0
        self.lock = threading.RLock()

    def _fetch_result(self, token, request_timeout):
        time_spent = 0
        while time_spent < request_timeout:
            with self.lock:
                try:
                    # limit polling to once every 5 seconds
                    if self.last_updated + 5 < time.time():
                        # update capabilities information
                        self.client.retrieve_capabilities(self.url)
                        self.last_updated = time.time()
                except:
                    print(str(self.url) + " unreachable. Retrying in 5 seconds")

                # check results
                result = self.client.result_for(token)
                if isinstance(result, mplane.model.Exception):
                    print(result.__repr__())
                    self.client.forget(token)
                    return None
                elif isinstance(result, mplane.model.Receipt):
                    pass
                elif isinstance(result, mplane.model.Result):
                    addrs = list(result.schema_dict_iterator())
                    self.client.forget(token)
                    return addrs
                else:
                    # other result, just print it out
                    print(result)

            time.sleep(5)
            time_spent += 5

        raise TimeoutException("Could not complete address retrieval within timeout period.")

class BtDhtResolverClient(ResolverClient):
    def __init__(self, tls_state, resolver_url):
        super(BtDhtResolverClient, self).__init__(tls_state, resolver_url)

    def request(self, count, ipv='ip4', when = 'now ... future', request_timeout = 30):
        token = None
        with self.lock:
            label = 'btdhtspider-'+ipv
            try:
                spec = self.client.invoke_capability(label, when, { "btdhtspider.count": count, "btdhtspider.unique": True })
                token = spec.get_token()
            except KeyError as e:
                print("Specified URL does not support '"+label+"' capability.")
                raise e

        if token is None:
            raise ValueError("Could not acquire request token.")

        return self._fetch_result(token, request_timeout)

class EcnSpiderImp:
    QUEUED_MIN_LENGTH = 10

    ChunkJob = collections.namedtuple('ChunkJob', ['chunk_id', 'addrs', 'ipv', 'when', 'token'])

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
        while True:
            with self.lock:
                if self.pending_token is None and len(self.queued) > 0:
                    print("sending ecnspider request")
                    self.pending = self.queued.popleft()
                    label = 'ecnspider-'+self.pending.ipv
                    try:
                        spec = self.client.invoke_capability(label, self.pending.when,
                                                             { "destination."+self.pending.ipv: [addr[0] for addr in self.pending.addrs],
                                                               "destination.port": [addr[1] for addr in self.pending.addrs]})
                        self.pending_token = spec.get_token()
                    except KeyError as e:
                        print("Specified URL does not support '"+label+"' capability.")

                    if self.pending_token is None:
                        print("Could not acquire request token.")
                        self.finished[self.pending.chunk_id] = None
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
                        print("received result for chunk id: ", self.pending.chunk_id)
                        # add to results
                        self.client.forget(self.pending_token)
                        self.finished[self.pending.chunk_id] = list(result.schema_dict_iterator())
                        self.pending_token = None
                        self.pending = None
                    else:
                        # other result, just print it out
                        print(result)

            time.sleep(5)

    def need_chunk(self):
        with self.lock:
            return len(self.queued) < EcnSpiderImp.QUEUED_MIN_LENGTH

    def add_chunk(self, addrs, chunk_id, ipv, when):
        with self.lock:
            self.queued.append(EcnSpiderImp.ChunkJob(chunk_id, addrs, ipv, when, None))

class EcnSpiderClient:
    # queued chunks - in queue to be sent to ecnspider component, feeder thread loads addresses
    # pending chunks - currently processing
    # finished chunks - finished, interrupted chunks or chunks which encountered an exception, consumer thread takes finished chunks and do further investigation

    def __init__(self, count, tls_state, ecnspiders_name_and_urls, resolver, chunk_size = 200, ipv='ip4'):
        self.chunk_size = chunk_size
        self.ipv = ipv
        self.imps = [EcnSpiderImp(name, tls_state, url) for name, url in ecnspiders_name_and_urls]

        self.lock = threading.RLock()

        self.feeder_thread = threading.Thread(target=self.feeder, daemon=True, name="feeder")
        self.consumer_thread = threading.Thread(target=self.consumer, daemon=True, name="consumer")

        self.resolver = resolver

        self.count = 0


        self.feeder_thread.start()
        self.consumer_thread.start()

    def feeder(self):
        print("feeder started")
        next_chunk_id = 0
        while True:
            if any([imp.need_chunk() for imp in self.imps]):
                print("adding chunk")
                addrs = [(row['destination.'+self.ipv], row['destination.port']) for row in self.resolver.request(self.chunk_size, ipv=self.ipv)]

                for imp in self.imps:
                    imp.add_chunk(addrs, next_chunk_id, self.ipv, "now ... future")

                next_chunk_id += 1

            time.sleep(1)

    def consumer(self):
        print("consumer started")
        while True:
            chunks_finished = None
            for imp in self.imps:
                with imp.lock:
                    if chunks_finished is None:
                        chunks_finished = set(imp.finished.keys())
                    else:
                        chunks_finished &= set(imp.finished.keys())

            if len(chunks_finished) == 0:
                time.sleep(5)
                continue

            merged_chunks = {}
            for chunk_id in chunks_finished:
                merged_chunk = {}
                for imp in self.imps:
                    with imp.lock:
                        merged_chunk[imp.name] = imp.finished.pop(chunk_id)

                merged_chunks[chunk_id] = merged_chunk

            print("merged results:", merged_chunks)



"""
class Client:
    def __init__(self, count, tls_state, resolver_url, probes_url):
        self.count = count


        self.probes = []
        for probe_url in probes_url:
            probe = mplane.client.HttpInitiatorClient(tls_state)
            probe.retrieve_capabilities(probe_url)
            self.probes.append(probe)

        self.stage_resolver = collections.deque()
        self.stage_ecnspider = collections.deque()
        self.stage_tracebox = collections.deque()
        self.stage_finished = collections.deque()

    def add_webresolver(self, hostname):
        self.stage_resolver.append(WebresolverOrder(hostname, STATUS_QUEUED, None, None))

    def add_btdhtresolver(self, count, ipv=4):
        self.stage_resolver.append((count, ipv))

    def handle_message(self, msg, identity):
        if isinstance(msg, mplane.model.Capability):
            pass

        elif isinstance(msg, mplane.model.Receipt):
            pass

        elif (isinstance(msg, mplane.model.Result) or
            isinstance(msg, mplane.model.Exception)):
            pass

        elif isinstance(msg, mplane.model.Withdrawal):
            pass

        elif isinstance(msg, mplane.model.Envelope):
            for imsg in msg.messages():
                self.handle_message(imsg, identity)
        else:
            raise ValueError("Internal error: unknown message "+repr(msg))

def retrieve_addresses(client, ipv, count, label, url, unique = True, when = "now ... future"):
    try:
        spec = client.invoke_capability(label, when, { "btdhtspider.count": count, "btdhtspider.unique": unique })
        token_label = spec.get_token()
    except KeyError as e:
        print("Specified URL does not support '"+label+"' capability.")
        raise e

    addrs = []

    while True:
        time.sleep(1)
        try:
            res = client.result_for(token_label)
        except KeyError:
            continue

        if isinstance(res, mplane.model.Exception):
            print(res.__repr__())
        elif isinstance(res, mplane.model.Receipt):
            continue
        elif isinstance(res, mplane.model.Result):
            for row in res.schema_dict_iterator():
                addrs.append((row['destination.'+ipv], row['destination.port'], row['btdhtspider.nodeid']))
        else:
            print(res)

        return addrs

def perform_measurement(clients, ipv, addrs, when = "now ... future"):
    # invoke on all probes
    ips = [str(addr[0]) for addr in addrs]
    ports = [addr[1] for addr in addrs]

    tokens = []
    for label, client in clients:
        try:
            spec = client.invoke_capability('ecnspider-'+ipv, when, { 'destination.'+ipv: ips, 'destination.port': ports })
            tokens.append((spec.get_token(), label, client))
        except KeyError as e:
            print("Specified URL does not support '"+label+"' capability.")
            raise e

    addrs = []
    for token, label, client in tokens:
        while True:
            time.sleep(1)
            try:
                res = client.result_for(token)
            except KeyError:
                continue

            if isinstance(res, mplane.model.Exception):
                print(res.__repr__())
            elif isinstance(res, mplane.model.Receipt):
                continue
            elif isinstance(res, mplane.model.Result):
                print("Receiving data from "+label)
                for row in res.schema_dict_iterator():
                    yield (label, row)
            else:
                print(res)

            break

if __name__ == "__main__":
    mplane.model.initialize_registry()

    # look for TLS configuration
    parser = argparse.ArgumentParser(description="mPlane ecnspider client")
    parser.add_argument('--config', metavar="config-file", required=True,
                        help="Configuration file")
    parser.add_argument('--count', metavar="N", type=int, required=True,
                        help="Number of test subjects for the measurement. (N > 0)")
    parser.add_argument('--file', '-f', metavar='FILENAME', help='Write results into CSV-File.', dest='outfile', required=True, type=argparse.FileType('w'))
    args = parser.parse_args()

    # check arguments
    if args.count < 1:
        print('\nERROR: Number of test subjects (--count) must be integer greater than 0.)')
        exit(1)

    # read the configuration file
    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(mplane.utils.search_path(args.config))

    tls_state = mplane.tls.TlsState(config)
    chunk_size = config['client'].getint('chunk_size')
    outfile = args.outfile

    # setup address collector
    if 'btdhtspider-ip6' in config['client']:
        ipv = 'ip6'
        btdht_label = 'btdhtspider-ip6'
        btdht_url = config['client'].get('btdhtspider-ip6')
    else:
        ipv = 'ip4'
        btdht_label = 'btdhtspider-ip4'
        btdht_url = config['client'].get('btdhtspider-ip4')

    btdhtspider = mplane.client.HttpInitiatorClient(tls_state)
    btdhtspider.retrieve_capabilities(btdht_url)

    # setup ecnspider probes
    probes_config = config.items('ecnspider')
    if len(probes_config) == 0:
        print('\nERROR: no ecnspider probes specified in configuration file.')
        exit(1)

    probes = []
    column_names = None
    for probe_label, probe_url in probes_config:
        probe_client = mplane.client.HttpInitiatorClient(tls_state)
        probe_client.retrieve_capabilities(probe_url)

        if column_names == None:
            cap = probe_client.capability_for('ecnspider-'+ipv)
            column_names = cap.result_column_names()

        probes.append((probe_label, probe_client))


    # write file header
    outfile.write("site,ip,port,rport,ecnstate,connstate,fif,fsf,fuf,fir,fsr,fur,ttl\n")

    recorded = 0
    try:
        while recorded < args.count:
            num_request = chunk_size if recorded + chunk_size < args.count else args.count - recorded
            assert(num_request > 0)

            print("Retrieving the next {} addresses.\n".format(num_request))
            addrs = retrieve_addresses(btdhtspider, ipv, num_request, btdht_label, btdht_url, unique=True)

            print("Performing measurement.")
            results = perform_measurement(probes, ipv, addrs)
            for label, result in results:
                outfile.write('{label},{ip},{port},{rport},{ecnstate},{connstate},{fif},{fsf},{fuf},{fir},{fsr},{fur},{ttl}\n'.format(
                    label=label,
                    ip=result['destination.'+ipv],
                    port=result['source.port'],
                    rport=result['destination.port'],
                    ecnstate=result['ecnspider.ecnstate'],
                    connstate=result['connectivity.ip'],
                    fif=result['ecnspider.initflags.fwd'],
                    fsf=result['ecnspider.synflags.fwd'],
                    fuf=result['ecnspider.unionflags.fwd'],
                    fir=result['ecnspider.initflags.rev'],
                    fsr=result['ecnspider.synflags.rev'],
                    fur=result['ecnspider.unionflags.rev'],
                    ttl=result['ecnspider.ttl.rev.min']
                ))

            recorded += num_request
            print("Finished {} of {}".format(recorded, args.count))
    except KeyboardInterrupt:
        print("Keyboard interrupt, closing file...")
    finally:
        outfile.close()
"""