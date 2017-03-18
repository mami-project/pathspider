import struct
import socket

from dnslib.dns import DNSError, DNSRecord, DNSQuestion, QTYPE
from scapy.all import RandShort

from pathspider.base import CONN_OK
from pathspider.base import CONN_TIMEOUT
from pathspider.base import CONN_FAILED


class PSDNSRecord(DNSRecord):
    def spider_send(self, source, job, conn_timeout, tcp=False):
        """
        Send packet to nameserver and return response and source port.
        """
        data = self.pack()
        if ':' in job['dip']:
            inet = socket.AF_INET6
        else:
            inet = socket.AF_INET
        if tcp:
            if len(data) > 65535:
                raise ValueError("Packet length too long: %d" % len(data))
            data = struct.pack("!H", len(data)) + data
            sock = socket.socket(inet, socket.SOCK_STREAM)
            if ':' in job['dip']:
                sock.bind((source[1], 0))
            else:
                sock.bind((source[0], 0))
            sock.settimeout(conn_timeout)
            sock.connect((job['dip'], job['dp']))
            sock.sendall(data)
            sp = sock.getsockname()[1]
            response = None
            try:
                response = sock.recv(8192)
                length = struct.unpack("!H",bytes(response[:2]))[0]
                while len(response) - 2 < length:
                    response += sock.recv(8192)
            except socket.timeout:
                pass
            if response is not None and len(response) > 2:
                try:
                    response = response[2:]
                    PSDNSRecord().parse(response)
                except DNSError:
                    response = None
            sock.close()
        else:
            sp = RandShort()
            sock = socket.socket(inet, socket.SOCK_DGRAM)
            if ':' in job['dip']:
                sock.bind((source[1], sp))
            else:
                sock.bind((source[0], sp))
            sp = sock.getsockname()[1]
            sock.settimeout(conn_timeout)
            sock.sendto(self.pack(), (job['dip'], job['dp']))
            response = None
            try:
                response, server = sock.recvfrom(8192)
            except socket.timeout:
                pass
            if response is not None:
                try:
                    PSDNSRecord().parse(response)
                except DNSError:
                    response = None
            sock.close()
        return (response, sp)


def connect_dns_tcp(source, job, conn_timeout):
    """
    This helper function will perform a DNS query over a TCP connection. It
    will not perform any special action in the event that this is the
    experimental flow, it only performs a DNS query connection.
    """

    return connect_dns(source, job, conn_timeout, tcp=True)

def connect_dns_udp(source, job, conn_timeout):
    """
    This helper function will perform a DNS query over a TCP connection. It
    will not perform any special action in the event that this is the
    experimental flow, it only performs a DNS query connection.
    """

    return connect_dns(source, job, conn_timeout, tcp=False)

def connect_dns(source, job, conn_timeout, tcp=False):
    """
    This helper function will perform a DNS query over a TCP connection. It
    will not perform any special action in the event that this is the
    experimental flow, it only performs a DNS query connection.
    """

    try:
        q = PSDNSRecord(q=DNSQuestion(job['domain'], QTYPE.A))
        response, sp = q.spider_send(source, job, conn_timeout, tcp=tcp)
        if response is None:
            return {'sp': sp, 'spdr_state': CONN_FAILED}
        return {'sp': sp, 'spdr_state': CONN_OK}
    except TimeoutError:
        return {'sp': 0, 'spdr_state': CONN_TIMEOUT}
    except TypeError:  # Caused by not having a v4/v6 address when trying to bind
        return {'sp': 0, 'spdr_state': CONN_FAILED}
    except OSError:
        return {'sp': 0, 'spdr_state': CONN_FAILED}
    except ValueError: # Caused by domain names that don't fit in a DNS query (this should never happen)
        return {'sp': 0, 'spdr_state': CONN_FAILED}
