
import logging
from timeit import default_timer as timer

from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.desync import DesynchronizedSpider
from pathspider.helpers.tcp import connect_http
from pathspider.observer import Observer
from pathspider.observer.base import BasicChain
from pathspider.observer.tcp import TCPChain
from pathspider.observer.tfo import TFOChain

# TODO: Create a DNS helper
#import struct
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

    name = "tfo"
    description = "TCP Fast Open"
    chains = [BasicChain, TCPChain, TFOChain]

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         args=args)
        self.conn_timeout = args.timeout

    def conn_no_tfo(self, job, config):
        return connect_http(self.source, job, self.conn_timeout)

    def conn_tfo(self, job, config):
        curlopts = {CURLOPT_TCP_FASTOPEN: 1}
        return connect_http(self.source, job, self.conn_timeout, curlopts)

    connections = [conn_no_tfo, conn_tfo, conn_tfo]

    def combine_flows(self, flows):
        conditions = []

        if (not flows[0]['spdr_state'] == CONN_OK and
                not flows[2]['spdr_state'] == CONN_OK):
            conditions.append('tfo.connectivity.offline')
        elif (not flows[0]['spdr_state'] == CONN_OK and
              flows[2]['spdr_state'] == CONN_OK):
            conditions.append('tfo.connectivity.transient')
        elif (flows[2]['spdr_state'] == CONN_OK and
              flows[2]['spdr_state'] == CONN_OK):
            conditions.append('tfo.connectivity.works')
            if flows[2]['observed']:
                if flows[2]['tfo_synclen']:
                    conditions.append('tfo.cookie.received')
                    if flows[2]['tfo_ack'] - flows[2]['tfo_seq'] == flows[2]['tfo_dlen'] + 1:
                        conditions.append('tfo.syndata.acked')
                    elif (flows[2]['tfo_ack'] - flows[2]['tfo_seq'] == 1) and flows[2]['tfo_dlen'] > 0:
                        conditions.append('tfo.syndata.not_acked')
                    elif flows[2]['tfo_ack'] == 0:
                        conditions.append('tfo.syndata.failed')
                else:
                    conditions.append('tfo.cookie.not_received')
        else:
            conditions.append('tfo.connectivity.broken')

        return conditions
