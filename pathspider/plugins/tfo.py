
import logging
import socket
import struct

from dnslib import DNSQuestion
from dnslib import QTYPE

from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.base import CONN_FAILED
from pathspider.base import CONN_TIMEOUT
from pathspider.desync import DesynchronizedSpider
from pathspider.helpers.tcp import connect_http
from pathspider.helpers.dns import connect_dns_tcp
from pathspider.helpers.dns import PSDNSRecord
from pathspider.observer import Observer
from pathspider.observer.base import BasicChain
from pathspider.observer.tcp import TCPChain
from pathspider.observer.tfo import TFOChain

CURLOPT_TCP_FASTOPEN = 244

class TFO(DesynchronizedSpider, PluggableSpider):

    name = "tfo"
    description = "TCP Fast Open"
    chains = [BasicChain, TCPChain, TFOChain]
    connect_supported = ["http", "dnstcp"]

    def conn_no_tfo(self, job, config):
        if self.args.connect == "http":
            return connect_http(self.source, job, self.args.timeout)
        elif self.args.connect == "dnstcp":
            return connect_dns_tcp(self.source, job, self.args.timeout)
        else:
            raise RuntimeError("Unknown connection mode specified")

    def conn_tfo(self, job, config):
        if self.args.connect == "http":
            curlopts = {CURLOPT_TCP_FASTOPEN: 1}
            return connect_http(self.source, job, self.args.timeout, curlopts)
        elif self.args.connect == "dnstcp":
            try:
                q = PSDNSRecord(q=DNSQuestion(job['domain'], QTYPE.A))
                data = q.pack()
                data = struct.pack("!H", len(data)) + data
                if ':' in job['dip']:
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.bind((self.source[1], 0))
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.bind((self.source[0], 0))
                # TODO: In non-blocking mode, this will always raise an EINPROGRESS
                # Should perform a blocking select afterwards, if it doesn't become available for
                # read then should fail it
                #sock.settimeout(self.args.timeout)
                sock.sendto(data, socket.MSG_FASTOPEN, (job['dip'], job['dp']))
                sp = sock.getsockname()[1]
                sock.close()
                return {'sp': sp, 'spdr_state': CONN_OK}
            except TimeoutError:
                return {'sp': sock.getsockname()[1], 'spdr_state': CONN_TIMEOUT}
                import traceback
                traceback.print_exc()
            except TypeError:  # Caused by not having a v4/v6 address when trying to bind
                import traceback
                traceback.print_exc()
                return {'sp': 0, 'spdr_state': CONN_FAILED}
            except OSError:
                import traceback
                traceback.print_exc()
                return {'sp': 0, 'spdr_state': CONN_FAILED}
        else:
            raise RuntimeError("Unknown connection mode specified")

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
