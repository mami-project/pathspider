
from scapy.all import IP         # pylint: disable=E0611
from scapy.all import IPv6       # pylint: disable=E0611
from scapy.all import UDP        # pylint: disable=E0611
from scapy.all import DNS        # pylint: disable=E0611
from scapy.all import DNSQR      # pylint: disable=E0611
from scapy.all import RandShort  # pylint: disable=E0611

import pathspider.base
from pathspider.base import PluggableSpider
from pathspider.forge import ForgeSpider
from pathspider.chains.basic import BasicChain
from pathspider.chains.dns import DNSChain

class UDPOpts(ForgeSpider, PluggableSpider):

    name = "udpopts"
    description = "UDP Options Trailer"
    version = pathspider.base.__version__
    chains = [BasicChain, DNSChain]
    packets = 2

    def forge(self, job, seq):
        sport = 0
        while sport < 1024:
            sport = int(RandShort())
        udp = (UDP(sport=sport, dport=job['dp'])/
               DNS(qd=DNSQR(qname=job['domain'])))
        if ':' in job['dip']:
            ip = IPv6(src=self.source[1], dst=job['dip'])
        else:
            ip = IP(src=self.source[0], dst=job['dip'])
        pkt = ip/udp
        if seq == 1:
            pkt.getlayer(1).len = len(pkt.getlayer(1))
            return pkt/b"\x01\x00" # NOP, EOL
        return pkt

    def combine_flows(self, flows):
        for flow in flows:
            if not flow['observed']:
                return ['pathspider.not_observed']

        if flows[0]['dns_response_valid'] and flows[1]['dns_response_valid']:
            return ['udpopts.connectivity.works']
        if flows[0]['dns_response_valid'] and not flows[1]['dns_response_valid']:
            return ['udpopts.connectivity.broken']
        if not flows[0]['dns_response_valid'] and flows[1]['dns_response_valid']:
            return ['udpopts.connectivity.transient']
        else:
            return ['udpopts.connectivity.offline']
