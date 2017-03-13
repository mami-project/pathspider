
import sys
import logging
import traceback

from scapy.all import send

from pathspider.base import DesynchronizedSpider
from pathspider.network import ipv4_address
from pathspider.network import ipv6_address

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

class ForgeSpider(DesynchronizedSpider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count, libtrace_uri, args)

        self.src4 = ipv4_address(self.libtrace_uri[4:])
        self.src6 = ipv6_address(self.libtrace_uri[4:])

        self.chains = {
            'new_flow_chain': [basic_flow],
            'ip4_chain': [basic_count],
            'ip6_chain': [basic_count],
            'tcp_chain': [],
            'udp_chain': [],
        }
        extra_chains = self.add_chains()
        for ck in extra_chains.keys():
            if ck in self.chains.keys():
                self.chains[ck] += extra_chains[ck]

    def add_chains(self):
        return {}

    def pre_connect(self, job):
        self.setup(job)

    def setup(self, job):
        pass

    def connect(self, job, config):
        pkt = self.forge(job, config)
        send(pkt, verbose=0)
        return {'sp': pkt.getlayer(1).sport}

    def forge(self, job, config):
        raise NotImplementedError("Cannot register an abstract plugin")

    def create_observer(self):
        logger = logging.getLogger('ecn')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            **self.chains)
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

