
import logging
import struct
import socket
from timeit import default_timer as timer

from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK, CONN_FAILED, CONN_TIMEOUT, CONN_SKIPPED
from pathspider.classic import DesynchronizedSpider
from pathspider.observer import Observer
from pathspider.observer import BasicChain
from pathspider.observer.tcp import TCPChain

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

class TFOChain:

    def _tcpoptions(self, tcp):
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
    
    def _tfocookie(self, tcp):
        opts = self._tcpoptions(tcp)
    
        if TO_FASTOPEN in opts:
            return (TO_FASTOPEN, bytes(opts[TO_FASTOPEN]))
        elif TO_EXPA in opts and opts[TO_EXPA][0:2] == bytearray(TO_EXP_FASTOPEN):
            return (TO_EXPA, bytes(opts[TO_EXPA][2:]))
        elif TO_EXPB in opts and opts[TO_EXPB][0:2] == bytearray(TO_EXP_FASTOPEN):
            return (TO_EXPB, tuple(opts[TO_EXPA][2:]))
        else:
            return (None, None)
    
    def new_flow(self, rec, ip):
        rec['tfo_synkind'] = 0
        rec['tfo_ackkind'] = 0
        rec['tfo_synclen'] = 0
        rec['tfo_ackclen'] = 0
        rec['tfo_seq'] = 0
        rec['tfo_dlen'] = 0
        rec['tfo_ack'] = 0
    
        return True
    
    def tcp(self, rec, tcp, rev): # pylint: disable=unused-argument
        # Shortcut non-SYN
        if not tcp.syn_flag:
            return True
    
        # Check for TFO cookie and data on SYN
        if tcp.syn_flag and not tcp.ack_flag:
            (tfo_kind, tfo_cookie) = self._tfocookie(tcp)
            if tfo_kind is not None:
                rec['tfo_synkind'] = tfo_kind
                rec['tfo_synclen'] = len(tfo_cookie)
                rec['tfo_seq'] = tcp.seq_nbr
                rec['tfo_dlen'] = len(tcp.data) - tcp.doff*4
                rec['tfo_ack'] = 0
    
        # Look for ACK of TFO data (and cookie)
        elif tcp.syn_flag and tcp.ack_flag and rec['tfo_synkind']:
            rec['tfo_ack'] = tcp.ack_nbr
            (tfo_kind, tfo_cookie) = self._tfocookie(tcp)
            if tfo_kind is not None:
                rec['tfo_ackkind'] = tfo_kind
                rec['tfo_ackclen'] = len(tfo_cookie)
    
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

def encode_dns_question(qname):
    out = bytearray()
    for part in qname.split("."):
        out.append(len(part))
        for b in bytes(part, "us-ascii"):
            out.append(b)
    out.append(0)
    return bytes(out)

# given a job description, generate a message to send on the SYN with TFO
def message_for(job, phase):
    if job['dp'] == 80:
        # Web. Get / for the named host
        return bytes("GET / HTTP/1.1\r\nhost: "+str(job['domain'])+"\r\n\r\n", "utf-8")
    elif job['dp'] == 53:
        # DNS. Construct a question asking the server for its own address
        header = [0x0a75 + phase, 0x0100, 1, 0, 0, 0] # header: question, recursion OK
        return struct.pack("!6H", *header) + encode_dns_question(job['domain'])
    else:
        # No idea. Empty payload.
        return b''

## TFO main class
class TFO(DesynchronizedSpider, PluggableSpider):
    def __init__(self, worker_count, libtrace_uri, args):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         args=args)
        self.conn_timeout = args.timeout

    def connect(self, job, config):
        # determine ip version
        if job['dip'].count(':') >= 1:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET

        # initialise default timers
        rec = {'tfo_c0t': 0, 'tfo_c1t': 0}

        # regular TCP: add skip flag to job on timeout or error
        if config == 0:
            rec['client'] = socket.socket(af, socket.SOCK_STREAM)
            job['_tfo_baseline_failed'] = True
            try:
                tt = timer()
                rec['client'].settimeout(self.conn_timeout)
                rec['client'].connect((job['dip'], job['dp']))
                rec['tfo_c0t'] = timer() - tt

                job['_tfo_baseline_failed'] = False
                rec['spdr_state'] = CONN_OK
            except TimeoutError:
                rec['spdr_state'] = CONN_TIMEOUT
            except OSError:
                rec['spdr_state'] = CONN_FAILED

        # with TFO
        if config == 1:
            # skip if config zero failed
            if job['_tfo_baseline_failed']:
                return {'spdr_state': CONN_SKIPPED}
            # step one: request cookie
            try:
                # pylint: disable=no-member
                tt = timer()
                sock = socket.socket(af, socket.SOCK_STREAM)
                sock.sendto(message_for(job, 0), socket.MSG_FASTOPEN, (job['dip'], job['dp'])) # pylint: disable=no-member
                sock.close()
                rec['tfo_c0t'] = timer() - tt
            except:
                pass

            # step two: use cookie
            try:
                tt = timer()
                rec['client'] = socket.socket(af, socket.SOCK_STREAM)
                rec['client'].sendto(message_for(job, 1),
                                     socket.MSG_FASTOPEN,
                                     (job['dip'], job['dp'])) # pylint: disable=no-member
                rec['tfo_c1t'] = timer() - tt

                rec['spdr_state'] = CONN_OK
            except TimeoutError:
                rec['spdr_state'] = CONN_TIMEOUT
            except OSError:
                rec['spdr_state'] = CONN_FAILED

        # Get source port from the socket
        rec['sp'] = rec['client'].getsockname()[1]

        return rec

    def post_connect(self, job, rec, config):
        # try not shutting down
        # try:
        #     conn.sock.shutdown(socket.SHUT_RDWR)
        # except:
        #     pass

        if rec['spdr_state'] == CONN_SKIPPED:
            return

        try:
            rec['client'].close()
        except:
            pass

        rec.pop('client')

    def create_observer(self):
        logger = logging.getLogger('tfo')
        logger.info("Creating observer")
        return Observer(self.libtrace_uri,
                        chains=[BasicChain, TCPChain, TFOChain])

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('tfo', help="TCP Fast Open")
        parser.add_argument("--timeout", default=5, type=int,
                            help=("The timeout to use for attempted "
                                  "connections in seconds (Default: 5)"))
        parser.set_defaults(spider=TFO)
