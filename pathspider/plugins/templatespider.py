
import sys
import collections

from twisted.plugin import IPlugin
from zope.interface import implementer

from pathspider.base import Spider
from pathspider.base import ISpider
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

Connection = collections.namedtuple("Connection", ["client", "port", "state"])
SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                      "host", "config", "connstate"])

@implementer(ISpider, IPlugin)
class TemplateSpider(Spider):
    """
    A template PATHspider plugin.
    """

    def config_zero(self):
        # TODO: Write code for config zero

        pass

    def config_one(self):
        # TODO: Write code for config one

        pass

    def connect(self, job, pcs, config):
        # TODO: Write code for connection

        return Connection(sock, sock.getsockname()[1], CONN_x)

    def post_connect(self, job, conn, pcs, config):
        if conn.state == CONN_OK:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, True)
        else:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, False)

        return rec

    def create_observer(self):
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, ecnsetup],
                            ip4_chain=[basic_count],
                            ip6_chain=[basic_count])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def merge(self, flow, res):
        if flow == NO_FLOW:
            flow = {"dip": res.ip,
                    "sp": res.port,
                    "dp": res.rport,
                    "connstate": res.connstate,
                    "observed": False }
        else:
            flow['connstate'] = res.connstate
            flow['observed'] = True

        self.outqueue.put(flow)

templatespider = TemplateSpider()
