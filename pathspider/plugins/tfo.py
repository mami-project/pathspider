
import logging
#import struct
from timeit import default_timer as timer

from pathspider.base import PluggableSpider
from pathspider.classic import DesynchronizedSpider
from pathspider.helpers.tcp import connect_http
from pathspider.observer import Observer
from pathspider.observer.base import BasicChain
from pathspider.observer.tcp import TCPChain
from pathspider.observer.tfo import TFOChain

# TODO: Create a DNS helper
#
#def encode_dns_question(qname):
#    out = bytearray()
#    for part in qname.split("."):
#        out.append(len(part))
#        for b in bytes(part, "us-ascii"):
#            out.append(b)
#    out.append(0)
#    return bytes(out)
#
#def dns_query(job, phase):
#    # DNS. Construct a question asking the server for its own address
#    header = [0x0a75 + phase, 0x0100, 1, 0, 0, 0] # header: question, recursion OK
#    return struct.pack("!6H", *header) + encode_dns_question(job['domain'])

CURLOPT_TCP_FASTOPEN = 244

class TFO(DesynchronizedSpider, PluggableSpider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         args=args)
        self.conn_timeout = args.timeout

    def connect(self, job, config):
        # initialise default timers
        rec = {'tfo_c0t': 0, 'tfo_c1t': 0}

        if config == 0:
            tt = timer()
            rec.update(connect_http(self.source, job, self.conn_timeout))
            rec['tfo_c0t'] = timer() - tt
            return rec

        # with TFO
        if config == 1:
            curlopts = {CURLOPT_TCP_FASTOPEN: 1}

            # request cookie
            tt = timer()
            connect_http(self.source, job, self.conn_timeout, curlopts)
            rec['tfo_c0t'] = timer() - tt

            # use cookie
            tt = timer()
            rec.update(connect_http(self.source, job, self.conn_timeout, curlopts))
            rec['tfo_c1t'] = timer() - tt
            return rec

    def create_observer(self):
        logger = logging.getLogger('tfo')
        logger.info("Creating observer")
        return Observer(self.libtrace_uri,
                        chains=[BasicChain, TCPChain, TFOChain])

    def combine_flows(self, flows):
        conditions = []

        if not flows[0]['observed'] and not flows[1]['observed']:
            conditions.append('tfo.connectivity.offline')
        elif not flows[0]['observed'] and flows[1]['observed']:
            conditions.append('tfo.connectivity.transient')
        elif flows[1]['observed'] and flows[1]['tcp_connected']:
            conditions.append('tfo.connectivity.works')
            if flows[1]['tfo_synclen']:
                conditions.append('tfo.cookie.received')
                if flows[1]['tfo_ack'] - flows[1]['tfo_seq'] == flows[1]['tfo_dlen'] + 1:
                    conditions.append('tfo.syndata.acked')
                elif (flows[1]['tfo_ack'] - flows[1]['tfo_seq'] == 1) and flows[1]['tfo_dlen'] > 0:
                    conditions.append('tfo.syndata.not_acked')
                elif flows[1]['tfo_ack'] == 0:
                    conditions.append('tfo.syndata.failed')
            else:
                conditions.append('tfo.cookie.not_received')
        else:
            conditions.append('tfo.connectivity.broken')

        return conditions

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('tfo', help="TCP Fast Open")
        parser.add_argument("--timeout", default=5, type=int,
                            help=("The timeout to use for attempted "
                                  "connections in seconds (Default: 5)"))
        parser.set_defaults(spider=TFO)
