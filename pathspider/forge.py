
import logging

from scapy.all import send

from pathspider.network import ipv4_address
from pathspider.network import ipv6_address

from pathspider.classic import DesynchronizedSpider

from pathspider.observer import Observer
from pathspider.observer import BasicChain

class ForgeSpider(DesynchronizedSpider):

    chains = [BasicChain]

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count, libtrace_uri, args)

        self.__logger = logging.getLogger('forge')

        self.src4 = ipv4_address(self.libtrace_uri[4:])
        self.src6 = ipv6_address(self.libtrace_uri[4:])

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
        self.__logger.info("Creating observer")
        return Observer(self.libtrace_uri,
                        chains=self.chains)
