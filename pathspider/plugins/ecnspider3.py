
import sys
import logging
import subprocess
import traceback

import socket
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
                                                       "host", "ecnstate",
                                                       "connstate"])

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2

USER_AGENT = "pathspider"

## Chain functions

def tcpcompleted(rec, tcp, rev): # pylint: disable=W0612,W0613
    return not tcp.fin_flag

def ecnsetup(rec, ip):
    rec['ecn_zero'] = False
    rec['ecn_one'] = False
    rec['ce'] = False
    return True

def ecnflags(rec, tcp, rev):
    SYN = 0x02
    CWR = 0x40
    ECE = 0x80

    flags = tcp.flags

    if flags & SYN:
        if rev == 0:
            rec['fwd_syn_flags'] = flags
        if rev == 1:
            rec['rev_syn_flags'] = flags

    return True

def ecncode(rec, ip, rev):
    EZ = 0x01
    EO = 0x02
    CE = 0x03

    if (ip.traffic_class & EZ == EZ):
        rec['ecn_zero'] = True
    if (ip.traffic_class & EO == EO):
        rec['ecn_one'] = True
    if (ip.traffic_class & CE == CE):
        rec['ce'] = True

    return True

## ECNSpider main class

@implementer(ISpider, IPlugin)
class ECNSpider(Spider):

    def activate(self, worker_count, libtrace_uri):
        super().activate(worker_count=worker_count,
                         libtrace_uri=libtrace_uri)
        self.tos = None # set by configurator
        self.conn_timeout = 10

    def config_zero(self):
        logger = logging.getLogger('ecnspider3')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Configurator disabled ECN")

    def config_one(self):
        logger = logging.getLogger('ecnspider3')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Configurator enabled ECN")

    def connect(self, job, pcs, config):
        sock = socket.socket()

        try:
            sock.settimeout(self.conn_timeout)
            sock.connect((job[0], job[1]))

            return Connection(sock, sock.getsockname()[1], CONN_OK)
        except TimeoutError:
            return Connection(sock, sock.getsockname()[1], CONN_TIMEOUT)
        except OSError:
            return Connection(sock, sock.getsockname()[1], CONN_FAILED)

    def post_connect(self, job, conn, pcs, config):
        if conn.state == CONN_OK:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, True)
        else:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, False)

        try:
            conn.client.shutdown(socket.SHUT_RDWR)
        except:
            pass

        try:
            conn.client.close()
        except:
            pass

        return rec

    def create_observer(self):
        logger = logging.getLogger('ecnspider3')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, ecnsetup],
                            ip4_chain=[basic_count, ecncode],
                            ip6_chain=[basic_count, ecncode],
                            tcp_chain=[ecnflags, tcpcompleted])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def merge(self, flow, res):
        logger = logging.getLogger('ecnspider3')
        if flow == NO_FLOW:
            flow = {"dip": res.ip,
                    "sp": res.port,
                    "dp": res.rport,
                    "connstate": res.connstate,
                    "ecnstate": res.ecnstate,
                    "observed": False }
        else:
            flow['connstate'] = res.connstate
            flow['ecnstate'] = res.ecnstate
            flow['observed'] = True

        logger.debug("Result: " + str(flow))
        self.outqueue.put(flow)

ecnspider = ECNSpider()
