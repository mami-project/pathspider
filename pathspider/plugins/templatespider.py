
import sys
import collections

from pathspider.base import Spider
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

Connection = collections.namedtuple("Connection", ["host", "state"])
SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                       "host", "config",
                                                       "connstate"])

class TemplateSpider(Spider):
    """
    A template PATHspider plugin.
    """

    def config_zero(self):
        print("Configuration zero")

    def config_one(self):
        print("Configuration one")

    def connect(self, job, pcs, config):
        sock = "Hello"
        return Connection(sock, 1)

    def post_connect(self, job, conn, pcs, config):
        rec = SpiderRecord(job[0], job[1], job[2], config, True)
        return rec

    def create_observer(self):
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow],
                            ip4_chain=[basic_count],
                            ip6_chain=[basic_count])
        except:
            print("Observer would not start")
            sys.exit(-1)

    def merge(self, flow, res):
        if flow == NO_FLOW:
            flow = {"dip": res.ip,
                    "sp": res.port,
                    "dp": res.rport,
                    "observed": False}
        else:
            flow['observed'] = True

        self.outqueue.put(flow)

