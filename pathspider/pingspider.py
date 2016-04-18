
import sys
import logging
import subprocess

from base import Spider
from observer import Observer


class PingSpider(Spider):

    def __init__(self, worker_count, libtrace_uri, check_interrupt=None):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         check_interrupt=check_interrupt)
        self.tos = None # set by configurator
    
    def config_one(self):
        logger = logging.getLogger('pingspider')
        self.tos = 3
        logger.info("Configurated to one")

    def config_zero(self):
        logger = logging.getLogger('pingspider')
        self.tos = 0
        logger.info("Configurated to zero")

    def connect(self, job, pcs, config):
        logger = logging.getLogger('pingspider')
        print(subprocess.run(["ping","-c","1","-Q",str(self.tos),job], stdout=subprocess.PIPE))
        return "<Connection for {}>".format(job,)

    def post_connect(self, job, conn, pcs, config):
        logger = logging.getLogger('pingspider')
        logger.info("Post connect: " + str((job, pcs, config)))
        import collections
        SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "port"])
        return SpiderRecord(job, 0)

    def create_observer(self):
        logger = logging.getLogger('pingspider')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri)
        except:
            logger.error("Observer not cooperating, abandon ship")
            sys.exit()

    def merge(self, flow, res):
        logger = logging.getLogger('pingspider')
        logger.info("Merging " + str(flow) + " with " + str(res))

logging.getLogger('pingspider').setLevel(logging.DEBUG)
logging.getLogger('pathspider').setLevel(logging.DEBUG)
pingspider = PingSpider(2, "int:enp0s25")
pingspider.add_job("139.133.210.32")
pingspider.add_job("2001:630:241:210:569f:35ff:fe0a:116a")
pingspider.run()

while pingspider.running:
    pass

