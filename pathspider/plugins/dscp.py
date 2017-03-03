
import sys
import logging
import subprocess
import traceback
import socket
from datetime import datetime

from pathspider.base import SynchronizedSpider
from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.base import CONN_SKIPPED
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

from pathspider.observer.tcp import tcp_state_setup
from pathspider.observer.tcp import tcp_state
from pathspider.observer.tcp import TCP_SYN

## Chain functions

def dscp_setup(rec, ip):
    if ip.tcp:
        # we'll only care about these if it's TCP
        rec['dscp_mark_syn_fwd'] = None
        rec['dscp_mark_syn_rev'] = None

    rec['dscp_mark_data_fwd'] = None
    rec['dscp_mark_data_rev'] = None
    return True

def dscp_extract(rec, ip, rev):
    tos = ip.traffic_class
    dscp = tos >> 2

    if ip.tcp:
        if ip.tcp.flags & TCP_SYN == TCP_SYN:
            rec['dscp_mark_syn_rev' if rev else 'dscp_mark_syn_fwd'] = dscp
            return True
        if ip.tcp.payload is None:
            return True

    # If not TCP or TCP with payload
    data_key = 'dscp_mark_data_rev' if rev else 'dscp_mark_data_fwd'
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
                '-p', 'tcp', '-m', 'tcp', '--dport', str(self.args.tcp_port), '-j', 'DSCP',
                '--set-dscp', str(self.args.codepoint)])
        logger.debug("Configurator enabled DSCP marking")

    def connect(self, job, config):
        """
        Performs a TCP connection.
        """
        logger = logging.getLogger('dscp')

        if 'dp' in job.keys():
            if job['dp'] != self.args.tcp_port:
                logger.warning("Unable to process job due to destination port mismatch: " + str(job))
                return {'spdr_state': CONN_SKIPPED}
        else:
            job['dp'] = self.args.tcp_port

        rec = self.tcp_connect(job)

        try:
            rec['client'].shutdown(socket.SHUT_RDWR)
            rec['client'].close()
            # FIXME: This is intended to ensure the connection is done and
            # won't see futher packets after the next configuration, but the
            # observer functions could also be made more robust too.
        except:
            pass

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
                            new_flow_chain=[basic_flow, tcp_state_setup, dscp_setup],
                            ip4_chain=[basic_count, dscp_extract],
                            ip6_chain=[basic_count, dscp_extract],
                            tcp_chain=[tcp_state])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def combine_flows(self, flows):
        conditions = []

        # discard non-observed flows
        for f in flows:
            if not (f['observed']):
                return

        baseline = 'dscp.' + str(flows[0]['dscp_mark_syn_fwd']) + '.'
        test = 'dscp.' + str(flows[1]['dscp_mark_syn_fwd']) + '.'

        if flows[0]['spdr_state'] == CONN_OK and flows[1]['spdr_state'] == CONN_OK:
            cond_conn = test + 'connectivity.works'
        elif flows[0]['spdr_state'] == CONN_OK and not flows[1]['spdr_state'] == CONN_OK:
            cond_conn = test + 'connectivity.broken'
        elif not flows[0]['spdr_state'] == CONN_OK and flows[1]['spdr_state'] == CONN_OK:
            cond_conn = test + 'connectivity.transient'
        else:
            cond_conn = test + 'connectivity.offline'
        conditions.append(cond_conn)

        conditions.append(test + 'replymark:' + str(flows[0]['dscp_mark_syn_rev']))
        conditions.append(baseline + 'replymark:' + str(flows[1]['dscp_mark_syn_rev']))

        return conditions

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('dscp', help='DiffServ Codepoints')
        parser.set_defaults(spider=DSCP)
        parser.add_argument("--codepoint", type=int, choices=range(0,64), default='48', metavar="[0-63]", help="DSCP codepoint to send (Default: 48)")
        parser.add_argument("--tcp-port", type=int, choices=range(1,65535), default='80', metavar="[1-65535]", help="Destination TCP port to connect to (Default: 80)")
