
import sys
import logging
import subprocess
import traceback

import socket
import collections

from pathspider.base import Spider
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

from pathspider.observer.tcp import tcp_setup
from pathspider.observer.tcp import tcp_complete

Connection = collections.namedtuple("Connection", ["client", "port", "state"])
TFOSpiderRecord = collections.namedtuple("TFOSpiderRecord", ["ip", "rport", "port",
                                                       "host", "tfostate",
                                                       "connstate", "rank"])

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2

USER_AGENT = "pathspider"

## Chain functions

TO_EOL = 0
TO_NOP = 1
TO_MSS = 2
TO_WS = 3
TO_SACKOK = 4
TO_SACK = 5
TO_TS = 8
TO_MPTCP = 30
TO_FASTOPEN = 34
TO_EXPA = 254
TO_EXPB = 255
TO_EXP_FASTOPEN = (0xF9, 0x89)

def _tcpoptions(tcp):
    """
    Given a TCP header, make TCP options available
    according to the interface we've designed for python-libtrace

    """
    optbytes = tcp.data[20:tcp.doff*4]
    opthash = {}

    # shortcut empty options
    if len(optbytes) == 0:
        return opthash

    # parse options in place
    cp = 0
    ncp = 0

    while cp < len(optbytes):
        # skip NOP
        if optbytes[cp] == TO_NOP:
            cp += 1
            continue
        # die on EOL
        if optbytes[cp] == TO_EOL:
            break

        # parse options length
        ncp = cp + optbytes[cp+1]

        # copy options data into hash
        # FIXME doesn't handle multiples
        opthash[optbytes[cp]] = optbytes[cp+2:ncp]

        # advance
        cp = ncp

    return opthash

def _tfocookie(tcp):
    opts = _tcpoptions(tcp)

    if TO_FASTOPEN in opts:
        return (TO_FASTOPEN, bytes(opts[TO_FASTOPEN]))
    elif TO_EXPA in opts and opts[TO_EXPA][0:2] == bytearray(TO_EXP_FASTOPEN):
        return (TO_EXPA, bytes(opts[TO_EXPA][2:]))
    elif TO_EXPB in opts and opts[TO_EXPB][0:2] == bytearray(TO_EXP_FASTOPEN):
        return (TO_EXPB, tuple(opts[TO_EXPA][2:]))
    else:
        return (None, None)

def _tfosetup(rec, ip):
        rec['tfo_kind'] = 0
        rec['tfo_cklen'] = 0
        rec['tfo_seq'] = 0
        rec['tfo_len'] = 0
        rec['tfo_ack'] = 0

def _tfopacket(rec, tcp, rev):
    # Shortcut non-SYN
    if not tcp.syn_flag:
        return True

    # Check for TFO cookie and data on SYN
    if tcp.syn_flag and not tcp.ack_flag:
        (tfo_kind, tfo_cookie) = _tfocookie(tcp)
        if tfo_kind is not None:
            rec['tfo_kind'] = tfo_kind
            rec['tfo_cklen'] = len(tfo_cookie)
            rec['tfo_seq'] = tcp.seq_nbr
            rec['tfo_len'] = len(tcp.data) - tcp.doff*4
            rec['tfo_ack'] = 0

    # Look for ACK of TFO data
    elif tcp.syn_flag and tcp.ack_flag and rec['tfo_kind']:
        rec['tfo_ack'] = tcp.ack_nbr

    # tell observer to keep going
    return True

# def test_tfocookie(fn=_tfocookie):
#     """
#     Test the _tfocookie() options parser on a static packet dump test file.
#     This is used mainly for performance evaluation of the parser for now,
#     and does not check for correctness.

#     """
#     import plt as libtrace

#     lturi = "pcapfile:testdata/tfocookie.pcap"
#     trace = libtrace.trace(lturi)
#     trace.start()
#     pkt = libtrace.packet()
#     cookies = 0
#     nocookies = 0

#     while trace.read_packet(pkt):
#         if not pkt.tcp:
#             continue

#         # just do the parse
#         if fn(pkt.tcp):
#             cookies += 1
#         else:
#             nocookies += 1

#     print("cookies: %u, nocookies: %u" % (cookies, nocookies))


## TFO main class

class TFO(Spider):

    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         args=args)
        self.tos = None # set by configurator
        self.conn_timeout = 10

    def config_zero(self):
        pass

    def config_one(self):
        pass

    def connect(self, job, pcs, config):
        # determine ip version
        if job[0].count(':') >= 1:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        # regular TCP
        if config == 0:
            sock = socket.socket(af, socket.SOCK_STREAM)

            try:
                sock.settimeout(self.conn_timeout)
                sock.connect((job[0], job[1]))

                return Connection(sock, sock.getsockname()[1], CONN_OK)
            except TimeoutError:
                return Connection(sock, sock.getsockname()[1], CONN_TIMEOUT)
            except OSError:
                return Connection(sock, sock.getsockname()[1], CONN_FAILED)

        # with TFO
        if config == 1:
            message = bytes("GET / HTTP/1.1\r\nhost: "+str(job[2])+"\r\n\r\n", "utf-8")

            # step one: request cookie
            try:
                # pylint: disable=no-member
                sock = socket.socket(af, socket.SOCK_STREAM)
                sock.sendto(message, socket.MSG_FASTOPEN, (job[0], job[1]))
                sock.close()
            except:
                pass

            # step two: use cookie
            try:
                sock = socket.socket(af, socket.SOCK_STREAM)
                sock.sendto(message, socket.MSG_FASTOPEN, (job[0], job[1]))

                return Connection(sock, sock.getsockname()[1], CONN_OK)
            except TimeoutError:
                return Connection(sock, sock.getsockname()[1], CONN_TIMEOUT)
            except OSError:
                return Connection(sock, sock.getsockname()[1], CONN_FAILED)

    def post_connect(self, job, conn, pcs, config):
        if conn.state == CONN_OK:
            rec = TFOSpiderRecord(job[0], job[1], conn.port, job[2], config, True, job[3])
        else:
            rec = TFOSpiderRecord(job[0], job[1], conn.port, job[2], config, False, job[3])

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
        logger = logging.getLogger('tfo')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri,
                            new_flow_chain=[basic_flow, tcp_setup, _tfosetup],
                            ip4_chain=[basic_count],
                            ip6_chain=[basic_count],
                            tcp_chain=[tcp_complete, _tfopacket])
        except:
            logger.error("Observer not cooperating, abandon ship")
            traceback.print_exc()
            sys.exit(-1)

    def merge(self, flow, res):
        logger = logging.getLogger('tfo')
        if flow == NO_FLOW:
            flow = {"dip": res.ip, "sp": res.port, "dp": res.rport, "connstate": res.connstate, "tfostate": res.tfostate, "observed": False }
        else:
            flow['connstate'] = res.connstate
            flow['host'] = res.host
            flow['rank'] = res.rank
            flow['tfostate'] = res.tfostate
            flow['observed'] = True

        logger.debug("Result: " + str(flow))
        self.outqueue.put(flow)

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('tfo', help="TCP Fast Open")
        parser.set_defaults(spider=TFO)

