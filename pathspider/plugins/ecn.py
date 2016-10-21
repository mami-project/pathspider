
import sys
import logging
import subprocess
import traceback
from datetime import datetime

import socket
import collections

from pathspider.base import SynchronizedSpider
from pathspider.base import PluggableSpider
from pathspider.base import Conn
from pathspider.base import NO_FLOW
from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count
from pathspider.observer.tcp import tcp_setup
from pathspider.observer.tcp import tcp_handshake
from pathspider.observer.tcp import tcp_complete
from pathspider.observer.tcp import TCP_SAE
from pathspider.observer.tcp import TCP_SAEC

SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                       "rank", "host", "config",
                                                       "connstate", "tstart", "tstop"])

USER_AGENT = "pathspider"

## Chain functions

def ecn_setup(rec, ip):
    fields = ['fwd_ez', 'fwd_eo', 'fwd_ce', 'rev_ez', 'rev_eo', 'rev_ce']
    for field in fields:
        rec[field] = False
    return True

def ecn_code(rec, ip, rev):
    EZ = 0x02
    EO = 0x01
    CE = 0x03

    if ip.traffic_class & CE == EZ:
        rec['rev_ez' if rev else 'fwd_ez'] = True
    if ip.traffic_class & CE == EO:
        rec['rev_eo' if rev else 'fwd_eo'] = True
    if ip.traffic_class & CE == CE:
        rec['rev_ce' if rev else 'fwd_ce'] = True

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

    def connect(self, job, pcs, config):
        """
        Performs a TCP connection.
        """

        return self.tcp_connect(job)

    def post_connect(self, job, conn, pcs, config):
        """
        Close the socket gracefully.
        """

        job_ip, job_port, job_host, job_rank = job

        tstop = str(datetime.utcnow())

        if conn.state == Conn.OK:
            rec = SpiderRecord(job_ip, job_port, conn.port, job_rank, job_host,
                               config, True, conn.tstart, tstop)
        else:
            rec = SpiderRecord(job_ip, job_port, conn.port, job_rank, job_host,
                               config, False, conn.tstart, tstop)

        try:
            conn.client.shutdown(socket.SHUT_RDWR)
        except: # FIXME: What are we catching?
            pass

        try:
            conn.client.close()
        except: # FIXME: What are we catching?
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

    def merge(self, flow, res):
        """
        Merge flow records.

        Includes the configuration and connection success or failure of the
        socket connection with the flow record.
        """

        logger = logging.getLogger('ecn')
        if flow == NO_FLOW:
            flow = {
                "dip": res.ip,
                "sp": res.port,
                "dp": res.rport,
                "observed": False,
                }
        else:
            flow['observed'] = True

        flow['rank'] = res.rank
        flow['host'] = res.host
        flow['connstate'] = res.connstate
        flow['config'] = res.config
        flow['tstart'] = res.tstart
        flow['tstop'] = res.tstop

        logger.debug("Result: " + str(flow))
        self.outqueue.put(flow)

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('ecn', help="Explicit Congestion Notification")
        parser.add_argument("--timeout", default=5, type=int, help="The timeout to use for attempted connections in seconds (Default: 5)")
        parser.set_defaults(spider=ECN)
