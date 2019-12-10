
from scapy.all import IPv6       # pylint: disable=E0611
from scapy.all import UDP        # pylint: disable=E0611
from scapy.all import DNS        # pylint: disable=E0611
from scapy.all import DNSQR      # pylint: disable=E0611
from scapy.all import RandShort  # pylint: disable=E0611

import pathspider.base
from pathspider.base import PluggableSpider
from pathspider.single import DesynchronizedSpider
from pathspider.chains.basic import BasicChain
from pathspider.chains.dns import DNSChain
from pathspider.helpers.dns import connect_dns_udp
from pathspider.helpers.dns import connect_dns

class HBHOPT(DesynchronizedSpider, PluggableSpider):

    name = "hbhopt"
    description = "Hop-by-hop options testing"
    version = pathspider.base.__version__
    chains = [BasicChain, DNSChain]


    def con_normal(self, job, config):
        return connect_dns_udp(self.source, job, self.args.timeout, sockopts=None)

    def con_hhb(self, job, config):
        opt =[(41, 54, b'\x00\x00\x00\x00\x00\x00\x00\x00')]
        return connect_dns_udp(self.source, job, self.args.timeout, sockopts=opt)

    def con_dopts(self, job, config):
        opt =[(41, 59, b'\x00\x00\x00\x00\x00\x00\x00\x00')]
        return connect_dns_udp(self.source, job, self.args.timeout, sockopts=opt)

    connections = [con_normal, con_hhb, con_dopts]

    def combine_flows(self, flows):
        for flow in flows:
            if not flow['observed']:
                return ['pathspider.not_observed']
        conditions = []
        conditions.append(self.combine_connectivity(flows[0]['dns_response_valid'],
                                          flows[1]['dns_response_valid'], prefix ='hbh_opts'))
        conditions.append(self.combine_connectivity(flows[0]['dns_response_valid'],
                                          flows[2]['dns_response_valid'], prefix='dst_opts'))
        return conditions
