
import sys
import logging
import subprocess
import traceback
import socket
from datetime import datetime

from pathspider.base import SynchronizedSpider
from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

from pathspider.observer.tcp import tcp_setup
from pathspider.observer.tcp import tcp_handshake
from pathspider.observer.tcp import tcp_complete
from pathspider.observer.tcp import TCP_SYN

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

    def connect(self, job, config):
        """
        Performs a TCP connection.
        """

        rec = self.tcp_connect(job)

        try:
            rec['client'].shutdown(socket.SHUT_RDWR)
            rec['client'].close()
            # FIXME: This is intended to ensure the connection is done and
            # won't see futher packets after the next configuration, but the
            # observer functions could also be made more robust too.
        except:
            pass

        rec['tstop'] = str(datetime.utcnow())
        rec.pop('client')

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

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('dscp', help='DiffServ Codepoints')
        parser.set_defaults(spider=DSCP)
        parser.add_argument("--codepoint", type=int, choices=range(0,64), default='48', metavar="[0-63]", help="DSCP codepoint to send (Default: 48)")
