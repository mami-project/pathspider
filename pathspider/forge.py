
import logging

from scapy.all import send

from pathspider.desync import DesynchronizedSpider

from pathspider.chains.basic import BasicChain

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
        if hasattr(cls, "connect_supported"):
            parser.add_argument(
                "--connect",
                type=str,
                choices=cls.connect_supported,
                default=cls.connect_supported[0],
                metavar="[{}]".format("|".join(cls.connect_supported)),
                help="Type of connection to perform (Default: {})".format(
                    cls.connect_supported[0]))
            for connect in cls.connect_supported:
                if connect.startswith('tor'):
                    parser.add_argument(
                        "--tor-path",
                        type=str,
                        help="A comma-seperated list of Tor relay fingerprints to use for building circuits"
                    )
                    break

        if hasattr(cls, "extra_args"):
            cls.extra_args(parser)
