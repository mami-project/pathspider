
import sys
import logging

from base import Spider
from observer import Observer

class NullSpider(Spider):

    def __init__(self, worker_count, libtrace_uri, check_interrupt=None):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         check_interrupt=check_interrupt)
    
    def config_one(self):
        logger = logging.getLogger('nullspider')
        logger.info("Configurated to one")

    def config_zero(self):
        logger = logging.getLogger('nullspider')
        logger.info("Configurated to zero")

    def connect(self, job, pcs, config):
        logger = logging.getLogger('nullspider')
        logger.info("Performing connect: " + str((job, pcs, config)))
        return "<Connection for {}>".format(job,)

    def post_connect(self, job, conn, pcs, config):
        logger = logging.getLogger('nullspider')
        logger.info("Post connect: " + str((job, pcs, config)))
        import collections
        SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "port"])
        return SpiderRecord(job, 0)

    def create_observer(self):
        logger = logging.getLogger('nullspider')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri)
        except:
            logger.error("Observer not cooperating, abandon ship")
            sys.exit()

    def merge(self, flow, res):
        logger = logging.getLogger('nullspider')
        logger.info("Merging " + str(flow) + " with " + str(res))

logging.getLogger('nullspider').setLevel(logging.DEBUG)
logging.getLogger('pathspider').setLevel(logging.DEBUG)
nullspider = NullSpider(2, "int:enp0s25")
nullspider.add_job("139.133.210.32")
nullspider.add_job("2001:630:241:210:569f:35ff:fe0a:116a")
nullspider.run()

while nullspider.running:
    pass

