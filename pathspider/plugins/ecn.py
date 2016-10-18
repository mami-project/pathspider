
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
from pathspider.observer.tcp import tcp_setup
from pathspider.observer.tcp import tcp_handshake
from pathspider.observer.tcp import tcp_complete
from pathspider.observer.tcp import TCP_SAE
from pathspider.observer.tcp import TCP_SAEW

Connection = collections.namedtuple("Connection", ["client", "port", "state", "tstart"])
SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                       "rank", "host", "ecnstate",
                                                       "connstate", "tstart", "tstop"])

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2

USER_AGENT = "pathspider"

## Chain functions

def ecn_setup(rec, ip):
    fields = ['fwd_ez', 'fwd_eo', 'fwd_ce', 'rev_ez', 'rev_eo', 'rev_ce']
    for field in fields:
        rec[field] = False
    return True

def ecn_code(rec, ip, rev):
    EZ = 0x01
    EO = 0x02
    CE = 0x03

    if (ip.traffic_class & EZ == EZ):
        if rev:
            rec['rev_ez'] = True
        else:
            rec['fwd_ez'] = True
    if (ip.traffic_class & EO == EO):
        if rev:
            rec['rev_eo'] = True
        else:
            rec['fwd_eo'] = True
    if (ip.traffic_class & CE == CE):
        if rev:
            rec['rev_ce'] = True
        else:
            rec['fwd_ce'] = True

    return True

## ECN main class

class ECN(SynchronizedSpider, PluggableSpider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         args=args)
        self.tos = None # set by configurator
        self.conn_timeout = 10
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

    def connect(self, job, pcs, config):
        """
        Performs a TCP connection.
        """

        job_ip, job_port, job_host, job_rank = job

        tstart = str(datetime.utcnow())

        if ":" in job_ip:
            sock = socket.socket(socket.AF_INET6)
        else:
            sock = socket.socket(socket.AF_INET)

        try:
            sock.settimeout(self.conn_timeout)
            sock.connect((job_ip, job_port))

            return Connection(sock, sock.getsockname()[1], CONN_OK, tstart)
        except TimeoutError:
            return Connection(sock, sock.getsockname()[1], CONN_TIMEOUT, tstart)
        except OSError:
            return Connection(sock, sock.getsockname()[1], CONN_FAILED, tstart)

    def post_connect(self, job, conn, pcs, config):
        """
        Close the socket gracefully.
        """

        job_ip, job_port, job_host, job_rank = job

        tstop = str(datetime.utcnow())

        if conn.state == CONN_OK:
            rec = SpiderRecord(job_ip, job_port, conn.port, job_rank, job_host, config, True, conn.tstart, tstop)
        else:
            rec = SpiderRecord(job_ip, job_port, conn.port, job_rank, job_host, config, False, conn.tstart, tstop)

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
        """
        Creates an observer with ECN-related chain functions.
        """

        logger = logging.getLogger('ecn')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, tcp_setup, ecn_setup],
                            ip4_chain=[basic_count, ecn_code],
                            ip6_chain=[basic_count, ecn_code],
                            tcp_chain=[tcp_handshake, tcp_complete])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def combine_flows(self, flow):
        dip = flow['dip']
        if dip in self.comparetab:
            other_flow = self.comparetab.pop(dip)

            # first has always ecn off, while the second has ecn on
            flows = (flow, other_flow) if other_flow['ecnstate'] else (other_flow, flow)
            conditions = []

            # discard non-observed flows and flows with no syn observed
            for f in flows:
                if not (f['observed'] and "rev_syn_flags" in f.keys()):
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

            if flows[1]['rev_syn_flags'] & TCP_SAEW == TCP_SAE:
                negotiated = True
                conditions.append('ecn.negotiated')
            else:
                negotiated = False
                conditions.append('ecn.not_negotiated')

            if flows[1]['rev_ez']:
                conditions.append('ecn.ect_zero.seen' if negotiated else 'ecn.ect_zero.unwanted')
            if flows[1]['rev_eo']:
                conditions.append('ecn.ect_one.seen' if negotiated else 'ecn.ect_one.unwanted')
            if flows[1]['rev_ce']:
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

    def merge(self, flow, res):
        """
        Merge flow records.

        Includes the configuration and connection success or failure of the
        socket connection with the flow record.
        """

        logger = logging.getLogger('ecn')
        if flow == NO_FLOW:
            flow = {"dip": res.ip,
                    "sp": res.port,
                    "dp": res.rport,
                    "observed": False }
        else:
            flow['observed'] = True

        flow['rank'] = res.rank
        flow['host'] = res.host
        flow['connstate'] = res.connstate
        flow['ecnstate'] = res.ecnstate
        flow['tstart'] = res.tstart
        flow['tstop'] = res.tstop

        logger.debug("Result: " + str(flow))
        self.combine_flows(flow)

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('ecn', help="Explicit Congestion Notification")
        parser.set_defaults(spider=ECN)
