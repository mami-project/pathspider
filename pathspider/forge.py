
import logging

from scapy.all import send

from pathspider.desync import DesynchronizedSpider

from pathspider.observer import Observer
from pathspider.observer.base import BasicChain

class ForgeSpider(DesynchronizedSpider):

    chains = [BasicChain]
    packets = 0

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count, libtrace_uri, args)

        self.__logger = logging.getLogger('forge')
        self._config_count = self.packets
        self.connections = [self.connect] * self.packets # pylint: disable=no-member

    def pre_connect(self, job):
        self.setup(job)

    def setup(self, job):
        pass

    def connect(self, job, seq):
        pkt = self.forge(job, seq)
        send(pkt, verbose=0)
        return {'sp': pkt.getlayer(1).sport}

    def forge(self, job, config):
        raise NotImplementedError("Cannot register an abstract plugin")

    @classmethod
    def register_args(cls, subparsers):
        # pylint: disable=no-member
        parser = subparsers.add_parser(cls.name, help=cls.description)
        parser.set_defaults(spider=cls)
        if hasattr(cls, "extra_args"):
            cls.extra_args(parser)
