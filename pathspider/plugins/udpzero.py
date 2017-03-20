
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

class UDPZero(ForgeSpider, PluggableSpider):

    name = "udpzero"
    description = "UDP Zero Checksum"
    version = pathspider.base.__version__
    chains = [BasicChain, DNSChain]
    packets = 2

    def forge(self, job, config):
        sport = 0
        while sport < 1024:
            sport = int(RandShort())
        udp = (UDP(sport=sport, dport=job['dp'])/
               DNS(qd=DNSQR(qname=job['domain'])))
        if ':' in job['dip']:
            ip = IPv6(src=self.source[1], dst=job['dip'])
        else:
            ip = IP(src=self.source[0], dst=job['dip'])
        if config == 1:
            udp.chksum = 0 # If not initialised, Scapy will calculate
        return ip/udp

    def combine_flows(self, flows):
        for flow in flows:
            if not flow['observed']:
                return ['pathspider.not_observed']

        if flows[0]['dns_response_valid'] and flows[1]['dns_response_valid']:
            return ['udpzero.connectivity.works']
        if flows[0]['dns_response_valid'] and not flows[1]['dns_response_valid']:
            return ['udpzero.connectivity.broken']
        if not flows[0]['dns_response_valid'] and flows[1]['dns_response_valid']:
            return ['udpzero.connectivity.transient']
        else:
            return ['udpzero.connectivity.offline']
