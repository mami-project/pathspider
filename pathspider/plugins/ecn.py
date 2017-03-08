
import sys
import logging
import subprocess
import traceback
from datetime import datetime

import socket
import collections

from pathspider.base import SynchronizedSpider
from pathspider.base import PluggableSpider
from pathspider.base import NO_FLOW
from pathspider.base import CONN_OK
from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count
from pathspider.observer.tcp import tcp_state_setup
from pathspider.observer.tcp import tcp_state
from pathspider.observer.tcp import TCP_SAE
from pathspider.observer.tcp import TCP_SAEC

## Chain functions

def ecn_setup(rec, ip):
    fields = ['ecn_ect0_fwd', 'ecn_ect1_fwd', 'ecn_ce_fwd', 'ecn_ect0_rev', 'ecn_ect1_rev', 'ecn_ce_rev']
    for field in fields:
        rec[field] = False
    return True

def ecn_code(rec, ip, rev):
    ECT_ZERO = 0x02
    ECT_ONE = 0x01
    ECT_CE = 0x03

    if ip.traffic_class & ECT_CE == ECT_ZERO:
        rec['ecn_ect0_rev' if rev else 'ecn_ect0_fwd'] = True
    if ip.traffic_class & ECT_CE == ECT_ONE:
        rec['ecn_ect1_rev' if rev else 'ecn_ect1_fwd'] = True
    if ip.traffic_class & ECT_CE == ECT_CE:
        rec['ecn_ce_rev' if rev else 'ecn_ce_fwd'] = True

    return True

## ECN main class

class ECN(SynchronizedSpider, PluggableSpider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         args=args)
        self.conn_timeout = args.timeout

    def config_zero(self):
        """
        Disables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug("Configurator disabled ECN")

    def config_one(self):
        """
        Enables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled ECN")

    def connect(self, job, config):
        """
        Performs a TCP connection.
        """

        return self.tcp_connect(job)

    def post_connect(self, job, conn, config):
        """
        Close the socket gracefully.
        """

        conn['sp'] = conn['client'].getsockname()[1]

        try:
            conn['client'].shutdown(socket.SHUT_RDWR)
        except: # FIXME: What are we catching?
            pass

        try:
            conn['client'].close()
        except: # FIXME: What are we catching?
            pass

        conn.pop('client')

    def create_observer(self):
        """
        Creates an observer with ECN-related chain functions.
        """

        logger = logging.getLogger('ecn')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, tcp_state_setup, ecn_setup],
                            ip4_chain=[basic_count, ecn_code],
                            ip6_chain=[basic_count, ecn_code],
                            tcp_chain=[tcp_state])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def combine_flows(self, flows):
        conditions = []

        # discard non-observed flows and flows with no syn observed
        for f in flows:
            if not (f['observed'] and f['tcp_connected']):
                return

        if flows[0]['spdr_state'] == CONN_OK and flows[1]['spdr_state'] == CONN_OK:
            conditions.append('ecn.connectivity.works')
        elif flows[0]['spdr_state'] == CONN_OK and not flows[1]['spdr_state'] == CONN_OK:
            conditions.append('ecn.connectivity.broken')
        elif not flows[0]['spdr_state'] == CONN_OK and not flows[1]['spdr_state'] == CONN_OK:
            conditions.append('ecn.connectivity.transient')
        else:
            conditions.append('ecn.connectivity.offline')

        if flows[1]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE:
            conditions.append('ecn.negotiation.succeeded')
        else:
            conditions.append('ecn.negotiation.failed')

        conditions.append('ecn.ipmark.ect0.seen' if flows[1]['ecn_ect0_rev'] else 'ecn.ipmark.ect0.not_seen')
        conditions.append('ecn.ipmark.ect1.seen' if flows[1]['ecn_ect1_rev'] else 'ecn.ipmark.ect1.not_seen')
        conditions.append('ecn.ipmark.ce.seen' if flows[1]['ecn_ce_rev'] else 'ecn.ipmark.ce.not_seen')

        return conditions

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('ecn', help="Explicit Congestion Notification")
        parser.add_argument("--timeout", default=5, type=int, help="The timeout to use for attempted connections in seconds (Default: 5)")
        parser.set_defaults(spider=ECN)
