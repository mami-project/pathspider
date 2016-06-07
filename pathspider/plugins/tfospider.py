
import sys
import logging
import subprocess

import socket
import collections

from twisted.plugin import IPlugin
from zope.interface import implementer

from pathspider.base import Spider
from pathspider.base import ISpider
from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

Connection = collections.namedtuple("Connection", ["client", "port", "state"])
#ecnstate? can it be changed to tfostate?
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

def tfosetup(rec, ip):
    print("tfosetup")
    rec['tfo_seq'] = -1000
    rec['tfo_len'] = -1000
    rec['tfo_working'] = 0

def tfocookie(tcp):
    options = tcp.data[20:tcp.doff*4]
    while True:
        if not options:
            return 0
        if (options[0] == 0):
            return 0
        if options[0] == 1:
            options = options[1:]
            continue
        if options[0] == 34:
            if options[1] == 2:
                return 0
            else:
                return 1
        else:
            if options[1] == len(options):
                return 0
            else:
                options = options[options[1]:]
                continue

def tfoworking(rec, tcp, rev):
    print("tfoworking")
    
    data_len = (len(tcp.data) - tcp.doff*4)
    has_cookie = tfocookie(tcp)
    has_data = (data_len > 0)
    outgoing = 1 #implement
    incomming = not outgoing
    
    if incomming and (tcp.ack_nbr == rec['tfo_seq'] + rec['tfo_len'] + 1):#TFO acknowledged
        rec['tfo_working'] = 1
        #signal success
        #exit flow
        
    if has_cookie and has_data and outgoing:#TFO data sent
        rec['tfo_seq'] = tcp.seq_nbr
        rec['tfo_len'] = data_len
    
    if outgoing and has_data and (tcp.seq_nbr == rec['tfo_seq'] + 1):#TCP fall back, retransmission
        rec['tfo_seq'] = -1000
        rec['tfo_len'] = -1000

## TFOSpider main class

@implementer(ISpider, IPlugin)
class TFOSpider(Spider):


    def activate(self, worker_count, libtrace_uri, check_interrupt=None):
        super().activate(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         check_interrupt=check_interrupt)
        self.tos = None # set by configurator
        self.conn_timeout = 10

    def config_zero(self):
        #systemwide changes not necessary if tfo is turned on once (is by default on my machine)
        pass
        """
        logger = logging.getLogger('ecnspider3')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Configurator disabled ECN")
        """

    def config_one(self):
        #systemwide changes not necessary if tfo is turned on once (is by default on my machine)
        pass
        """
        logger = logging.getLogger('ecnspider3')

        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Configurator enabled ECN")
        """

    def connect(self, job, pcs, config):

        #determine ip version
        print("connect")
        if job[0].count(':') >= 1: ipv = 6
        else: ipv = 4
        
        #regular TCP
        if config == 0:
            if ipv == 4:
                sock = socket.socket()
            else:
                sock = socket.socket(socket.AF_INET6)
        
            try:
                sock.settimeout(self.conn_timeout)
                sock.connect((job[0], job[1]))

                return Connection(sock, sock.getsockname()[1], CONN_OK)
            except TimeoutError:
                return Connection(sock, sock.getsockname()[1], CONN_TIMEOUT)
            except OSError:
                return Connection(sock, sock.getsockname()[1], CONN_FAILED)    
        
        #with TFO
        if config == 1:
            message = bytes("GET / HTTP/1.1\r\n\r\n", "utf-8")
            if ipv == 4:
                addr = socket.AF_INET
            else:
                addr = socket.AF_INET6
            
            #request cookie
            try:
                sock = socket.socket(addr, socket.SOCK_STREAM)
                sock.sendto(message, socket.MSG_FASTOPEN, (job[0], job[1]))
                sock.settimeout(self.conn_timeout)
                sock.recv(1)
                sock.close()
            except:
                pass
            
            #use cookie
            try:
                sock = socket.socket(addr, socket.SOCK_STREAM)
                sock.sendto(message, socket.MSG_FASTOPEN, (job[0], job[1]))
                sock.settimeout(self.conn_timeout)
                sock.recv(1)
                
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
        logger = logging.getLogger('tfospider')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, tfosetup],
                            ip4_chain=[basic_count],
                            ip6_chain=[basic_count],
                            tcp_chain=[tfoworking, tcpcompleted])
        except:
            logger.error("Observer not cooperating, abandon ship")
            sys.exit()

    def merge(self, flow, res):
        logger = logging.getLogger('tfospider')
        flow['connstate'] = res.connstate
        flow['ecnstate'] = res.ecnstate
        logger.info("Result: " + str(flow))
        self.merged_results.append(flow)

tfospider = TFOSpider()
