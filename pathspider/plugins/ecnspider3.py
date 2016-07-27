
import sys
import logging
import subprocess
import traceback
from datetime import datetime

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

Connection = collections.namedtuple("Connection", ["client", "port", "state", "tstart"])
SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                       "rank", "host", "ecnstate",
                                                       "connstate", "tstart", "tstop"])

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2

USER_AGENT = "pathspider"

TCP_CWR = 0x80
TCP_ECE = 0x40
TCP_ACK = 0x10
TCP_SYN = 0x02

TCP_SAEW = (TCP_SYN | TCP_ACK | TCP_ECE | TCP_CWR)
TCP_SAE = (TCP_SYN | TCP_ACK | TCP_ECE)

## Chain functions

def tcpcompleted(rec, tcp, rev): # pylint: disable=W0612,W0613
    return not tcp.fin_flag

def ecnsetup(rec, ip):
    rec['ecn_zero'] = False
    rec['ecn_one'] = False
    rec['ce'] = False
    return True

def ecnflags(rec, tcp, rev):
    flags = tcp.flags

    if flags & TCP_SYN:
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
        self.comparetab = {}
        self.logger = logging.getLogger('ecnspider3')

    def config_zero(self):
        """
        Disables ECN negotiation via sysctl.
        """
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.logger.debug("Configurator disabled ECN")

    def config_one(self):
        """
        Enables ECN negotiation via sysctl.
        """
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.logger.debug("Configurator enabled ECN")

    def connect(self, job, pcs, config):
        """
        Performs a TCP connection.
        """

        job_ip, job_port, job_host, job_rank = job

        tstart = datetime.utcnow()

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

        tstop = datetime.utcnow()

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

        self.logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, ecnsetup],
                            ip4_chain=[basic_count, ecncode],
                            ip6_chain=[basic_count, ecncode],
                            tcp_chain=[ecnflags, tcpcompleted])
        except:
            self.logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def combine_flows(self, flow):
        dip = flow['dip']
        if dip in self.comparetab:
            other_flow = self.comparetab.pop(dip)

            # first has always ecn off, while the second has ecn on
            flows = (flow, other_flow) if other_flow['ecnstate'] else (other_flow, flow)

            conditions = []

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

            if 'rev_syn_flags' in flows[1]:
                if flows[1]['rev_syn_flags'] & TCP_SAEW == TCP_SAE:
                    cond_nego = 'ecn.negotiated'
                else:
                    cond_nego = 'ecn.not_negotiated'

                conditions.append(cond_nego)

            # render datetime to strings
            flows[0]['tstart'] = flows[0]['tstart'].isoformat()
            flows[0]['tstop'] = flows[0]['tstop'].isoformat()

            flows[1]['tstart'] = flows[1]['tstart'].isoformat()
            flows[1]['tstop'] = flows[1]['tstop'].isoformat()

            result = {
                'sip': flow['sip'],
                'dip': dip,
                'dp': flow['dp'],
                'conditions': conditions,
                'hostname': flow['host'],
                'rank': flow['rank'],
                'flow_results': flows,
                'time': {
                    'from': tstart.isoformat(),
                    'to': tstop.isoformat()
                }
            }

            self.logger.debug("Combined result: " + str(result))
            self.outqueue.put(result)
        else:
            self.comparetab[dip] = flow

    def merge(self, flow, res):
        """
        Merge flow records.
        
        Includes the configuration and connection success or failure of the
        socket connection with the flow record.
        """
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

        self.logger.debug("Flow result: " + str(flow))
        self.combine_flows(flow)

ecnspider = ECNSpider()
