
import sys
import logging
import subprocess
import traceback

import socket
import collections

from pathspider.base import SynchronizedSpider
from pathspider.base import PluggableSpider
from pathspider.base import Conn
from pathspider.base import Connection
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

from pathspider.observer.tcp import tcp_setup
from pathspider.observer.tcp import tcp_handshake
from pathspider.observer.tcp import tcp_complete
from pathspider.observer.tcp import TCP_SYN

SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                       "host", "config",
                                                       "connstate"])

## Chain functions

def dscp_setup(rec, ip):
    if ip.tcp:
        # we'll only care about these if it's TCP
        rec['fwd_syn_dscp'] = None
        rec['rev_syn_dscp'] = None

    rec['fwd_data_dscp'] = None
    rec['rev_data_dscp'] = None
    return True

def dscp_extract(rec, ip, rev):
    tos = ip.traffic_class
    dscp = tos >> 2

    if ip.tcp:
        if ip.tcp.flags & TCP_SYN == TCP_SYN:
            rec['rev_syn_dscp' if rev else 'fwd_syn_dscp'] = dscp
            return True
        if ip.tcp.payload is None:
            return True

    # If not TCP or TCP with payload
    data_key = 'rev_data_dscp' if rev else 'fwd_data_dscp'
    rec[data_key] = rec[data_key] or dscp
    return True

## DSCP main class

class DSCP(SynchronizedSpider, PluggableSpider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         args=args)
        self.dscp = None # set by configurator
        self.conn_timeout = 10

    def config_zero(self):
        """
        Disables DSCP marking via iptables.
        """

        logger = logging.getLogger('dscp')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-F'])
        logger.debug("Configurator disabled DSCP marking")

    def config_one(self):
        """
        Enables DSCP marking via iptables.
        """

        logger = logging.getLogger('dscp')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-A', 'OUTPUT',
                '-p', 'tcp', '-m', 'tcp', '--dport', '80', '-j', 'DSCP',
                '--set-dscp', str(self.args.codepoint)])
        logger.debug("Configurator enabled DSCP marking")

    def connect(self, job, pcs, config):
        """
        Performs a TCP connection.
        """

        conn = self.tcp_connect(job)
        sock = conn.client

        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            # FIXME: This is intended to ensure the connection is done and
            # won't see futher packets after the next configuration, but the
            # observer functions could also be made more robust too.
        except:
            pass

        return conn

    def post_connect(self, job, conn, pcs, config):
        """
        Create the SpiderRecord
        """

        if conn.state == Conn.OK:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, True)
        else:
            rec = SpiderRecord(job[0], job[1], conn.port, job[2], config, False)

        return rec

    def create_observer(self):
        """
        Creates an observer with DSCP-related chain functions.
        """

        logger = logging.getLogger('dscp')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, tcp_setup, dscp_setup],
                            ip4_chain=[basic_count, dscp_extract],
                            ip6_chain=[basic_count, dscp_extract],
                            tcp_chain=[tcp_handshake, tcp_complete])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def merge(self, flow, res):
        """
        Merge flow records.

        Includes the configuration and connection success or failure of the
        socket connection with the flow record.
        """

        logger = logging.getLogger('dscp')
        if flow == NO_FLOW:
            flow = {"dip": res.ip,
                    "sp": res.port,
                    "dp": res.rport,
                    "connstate": res.connstate,
                    "config": res.config,
                    "observed": False }
        else:
            flow['connstate'] = res.connstate
            flow['config'] = res.config
            flow['observed'] = True

        logger.debug("Result: " + str(flow))
        self.outqueue.put(flow)

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('dscp', help='DiffServ Codepoints')
        parser.set_defaults(spider=DSCP)
        parser.add_argument("--codepoint", type=int, choices=range(1,64), default='1', metavar="[0-63]", help="DSCP codepoint to send (Default: 0)")
