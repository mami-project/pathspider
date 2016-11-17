
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
from pathspider.helpers import Http_Request
from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count
from pathspider.observer.tcp import tcp_setup
from pathspider.observer.tcp import tcp_handshake
from pathspider.observer.tcp import tcp_complete
from pathspider.observer.tcp import TCP_SAE
from pathspider.observer.tcp import TCP_SAEC

SpiderRecord = collections.namedtuple("SpiderRecord",
        ["ip", "rport", "port", "rank", "host", "config",
        "connstate", "tstart", "tstop"])

USER_AGENT = "pathspider"

CONN_SUCCES_INFO_STRING = "Number of succesfull HTTP requests"
CONN_FAIL_INFO_STRING = "Number of failed HTTP requests"
CONN_RATIO_INFO_STRING = "Ratio of succesfull HTTP requests"
CONN_SUCCES_INFO_KEY = "ECN_HTTP_SUCCES_CNT"
CONN_FAIL_INFO_KEY = "ECN_HTTP_FAIL_CNT"
CONN_RATIO_INFO_KEY = "ECN_HTTP_SUCCES_RATIO"

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
        self.comparetab = {}
        self.init_meta_info()

    def config_zero(self):
        """
        Disables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        logger.debug("Configurator disabled ECN")

    def config_one(self):
        """
        Enables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled ECN")

    def pre_connect(self, job, job_variables):
        job_variables['http_requests'] = [None, None]

        return None

    def connect(self, job, pcs, config, job_variables):
        """
        Performs a TCP connection.
        """

        job_ip, job_port, job_host, job_rank = job

        conn = self.tcp_connect(job)

        if conn.state == Conn.OK:
            job_variables['http_requests'][config] = \
                Http_Request(conn.client, job_host, method = 'HEAD')
            job_variables['http_requests'][config].send_request()

        return conn

    def post_connect(self, job, conn, pcs, config, job_variables):
        """
        Get webpage and close the socket gracefully.
        """
        logger = logging.getLogger('ecn')
        job_ip, job_port, job_host, job_rank = job

        if conn.state == Conn.OK:
            result = job_variables['http_requests'][config].receive_header()
            self.update_meta_info_after_http(result)

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

    def combine_flows(self, flow):
        logger = logging.getLogger('ecn')

        dip = flow['dip']

        # If the matching flow (with the other config), is not in the comparetab
        # yet, put this flow in there.
        if not (dip in self.comparetab):
            self.comparetab[dip] = flow
            return

        # Otherwise, if we already have matching flow (with the other config),
        # compare the two.
        other_flow = self.comparetab.pop(dip)

        flows = {}
        if flow['config']:
            flows['ecn'] = flow
            flows['no_ecn'] = other_flow
        else:
            flows['ecn'] = other_flow
            flows['no_ecn'] = flow
        conditions = []

        # We get some idea about start and stop times
        tstart = min(flow['tstart'], other_flow['tstart'])
        tstop = max(flow['tstop'], other_flow['tstop'])

        ## FIRST, we check if we can connect with ECN enabled
        # When we had a succesfull TCP handshake, flow['connstate']
        # will be True.

        # We could always connect
        if flows['no_ecn']['connstate'] and flows['ecn']['connstate']:
            conditions.append('ecn.connectivity.works')
        # We could only connect without ECN
        elif flows['no_ecn']['connstate'] and not flows['ecn']['connstate']:
            conditions.append('ecn.connectivity.broken')
        # We could only connect with ECN
        elif not flows['no_ecn']['connstate'] and flows['ecn']['connstate']:
            conditions.append('ecn.connectivity.transient')
        # We could not connect
        else:
            conditions.append('ecn.connectivity.offline')

        ## SECOND, we check if we observed the ECN flow, to see if we can do
        # some analysis on it
        if  flows['ecn']['observed']:

            ## THIRD, we check if ECN was properly negotiated
            # If we did not capture the reverse syn package, we can say nothing
            # about the negotiation
            if flows['ecn']['rev_syn_flags'] == None:
                pass
            # if the host has send a "ECN-setup SYN-ACK packet" (see RFC 3168)
            elif flows['ecn']['rev_syn_flags'] & TCP_SAEC == TCP_SAE:
                conditions.append('ecn.negotiated')
            else:
                conditions.append('ecn.not_negotiated')

            ## FOURTH, we check if we have seen the ECT or CE codepoints.
            # check ECT(0)
            if flows['ecn']['rev_ez']:
                    conditions.append('ecn.ect_zero.seen')

            # check ECT(1)
            if flows['ecn']['rev_eo']:
                    conditions.append('ecn.ect_one.seen')

            # check CE
            if flows['ecn']['rev_ce']:
                    conditions.append('ecn.ce.seen')

        ## FIFTH, put the result on the outqueue
        flow_tuple = (flows['no_ecn'], flows['ecn'])
        self.outqueue.put({
            'sip': flow['sip'],
            'dip': dip,
            'dp': flow['dp'],
            'conditions': conditions,
            'hostname': flow['host'],
            'rank': flow['rank'],
            'flow_results': flow_tuple,
            'time': {
                'from': tstart,
                'to': tstop
            }
        })

    def merge(self, flow, res):
        """
        Merge flow records.

        Includes the configuration and connection success or failure of the
        socket connection with the flow record.
        """

        logger = logging.getLogger('ecn')
        if flow == NO_FLOW:
            flow = {
                "sip": 'fixme', # FIXME
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
        self.combine_flows(flow)

    def init_meta_info(self):
        '''
        Initialises meta info variables of this spider.

        Should be called at initialisation.
        '''

        self.meta_info_strings[CONN_SUCCES_INFO_KEY] = CONN_SUCCES_INFO_STRING
        self.meta_info_strings[CONN_FAIL_INFO_KEY] = CONN_FAIL_INFO_STRING
        self.meta_info_strings[CONN_RATIO_INFO_KEY] = CONN_RATIO_INFO_STRING
        self.meta_info_values[CONN_SUCCES_INFO_KEY] = 0
        self.meta_info_values[CONN_FAIL_INFO_KEY] = 0
        self.meta_info_values[CONN_RATIO_INFO_KEY] = 0

    def update_meta_info_after_http(self, result):
        '''
        Update the meta info variables of this spider after a HTTP request

        :param result: A result as returned by the `http_request` method
        :type result: tuple(str, bytes, bool)
        '''

        succes = result[2]
        with self.meta_info_lock:
            if succes:
                self.meta_info_values[CONN_SUCCES_INFO_KEY] = \
                    self.meta_info_values[CONN_SUCCES_INFO_KEY] + 1
            else:
                self.meta_info_values[CONN_FAIL_INFO_KEY] = \
                    self.meta_info_values[CONN_FAIL_INFO_KEY] + 1

            # at least one of the values will be non equal to zero, so no
            # problem here
            succes_rate =  self.meta_info_values[CONN_SUCCES_INFO_KEY] / \
                        (self.meta_info_values[CONN_SUCCES_INFO_KEY] + \
                        self.meta_info_values[CONN_FAIL_INFO_KEY])
            self.meta_info_values[CONN_RATIO_INFO_KEY] = round(succes_rate, 3)

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('ecn',
                help="Explicit Congestion Notification")
        parser.add_argument("--timeout", default=5, type=int,
                help="The timeout to use for attempted connections "
                "in seconds (Default: 5)")
        parser.set_defaults(spider=ECN)
