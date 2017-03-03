
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
        self.comparetab = {}

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

    def combine_flows(self, flow):
        dip = flow['dip']
        if dip in self.comparetab:
            other_flow = self.comparetab.pop(dip)

            # first has always ecn off, while the second has ecn on
            flows = (flow, other_flow) if other_flow['config'] else (other_flow, flow)
            conditions = []

            # discard non-observed flows and flows with no syn observed
            for f in flows:
                if not (f['observed'] and f['rev_syn_flags'] != None):
                    return

            tstart = min(flow['tstart'], other_flow['tstart'])
            tstop = max(flow['tstop'], other_flow['tstop'])

            if flows[0]['connstate'] and flows[1]['connstate']:
                cond_conn = 'ecn.connectivity.works'
            elif flows[0]['connstate'] and not flows[1]['connstate']:
                cond_conn = 'ecn.connectivity.broken'
            elif not flows[0]['connstate'] and not flows[1]['connstate']:
                cond_conn = 'ecn.connectivity.transient'
            else:
                cond_conn = 'ecn.connectivity.offline'
            conditions.append(cond_conn)

            if flows[1]['rev_syn_flags'] & TCP_SAEC == TCP_SAE:
                negotiated = True
                conditions.append('ecn.negotiated')
            else:
                negotiated = False
                conditions.append('ecn.not_negotiated')

            if flows[1]['ecn_ect0_rev']:
                conditions.append('ecn.ect_zero.seen' if negotiated else 'ecn.ect_zero.unwanted')
            if flows[1]['ecn_ect1_rev']:
                conditions.append('ecn.ect_one.seen' if negotiated else 'ecn.ect_one.unwanted')
            if flows[1]['ecn_ce_rev']:
                conditions.append('ecn.ce.seen' if negotiated else 'ecn.ce.unwanted')

            self.outqueue.put({
                'sip': flow['sip'],
                'dip': dip,
                'dp': flow['dp'],
                'conditions': conditions,
                'hostname': flow['host'],
                'rank': flow['rank'],
                'flow_results': flows,
                'time': {
                    'from': tstart,
                    'to': tstop
                }
            })
        else:
            self.comparetab[dip] = flow

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('ecn', help="Explicit Congestion Notification")
        parser.add_argument("--timeout", default=5, type=int, help="The timeout to use for attempted connections in seconds (Default: 5)")
        parser.set_defaults(spider=ECN)
