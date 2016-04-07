
import sys

from base import Spider
from observer import Observer

class NullSpider(Spider):
    def __init__(self, worker_count, libtrace_uri, check_interrupt=None):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         check_interrupt=check_interrupt)
    
    def config_one(self):
        print("Configurated to one")

    def config_zero(self):
        print("Configurated to zero")

    def connect(self, job, pcs, config):
        print("Performing connect")

    def post_connect(self, job, conn, pcs, config):
        print("Post connect")

    def create_observer(self):
        print("Creating observer")
        try:
            return Observer(self.libtrace_uri)
        except:
            print("Observer not cooperating, abandon ship")
            sys.exit()

    def merge(self, flow, res):
        print("Merging " + str(flow) + " with " + str(res))

nullspider = NullSpider(10, "int:enp0s25")
nullspider.run()

