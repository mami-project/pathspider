
import logging
import struct
import socket
from timeit import default_timer as timer

from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK, CONN_FAILED, CONN_TIMEOUT, CONN_SKIPPED
from pathspider.classic import DesynchronizedSpider
from pathspider.observer import Observer
from pathspider.observer.base import BasicChain
from pathspider.observer.tcp import TCPChain

USER_AGENT = "pathspider"

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
                sock.sendto(message_for(job, 0), socket.MSG_FASTOPEN, (job['dip'], job['dp']))
                sock.close()
                rec['tfo_c0t'] = timer() - tt
            except:
                pass

            # step two: use cookie
            try:
                # pylint: disable=no-member
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
