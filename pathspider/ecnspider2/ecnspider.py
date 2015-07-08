"""
Ecnspider2: Qofspider-based tool for measuring ECN-linked connectivity
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

.. moduleauthor:: Brian Trammell <brian@trammell.ch>
.. moduleauthor:: Elio Gubser <elio.gubser@alumni.ethz.ch>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""

from ipaddress import ip_address
import http.client
import collections
import socket
import logging
import subprocess
import logging
import time
import sys
import ipfix
import itertools
from . import qofspider

# Flags constants
TCP_CWR = 0x80
TCP_ECE = 0x40
TCP_URG = 0x20
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_RST = 0x04
TCP_SYN = 0x02
TCP_FIN = 0x01

# QoF TCP Characteristics constants
QOF_SYNECT0 =    0x0100
QOF_SYNECT1 =    0x0200
QOF_SYNCE   =    0x0400
QOF_SYNTSOPT =   0x1000
QOF_SYNSACKOPT = 0x2000
QOF_SYNWSOPT =   0x4000
QOF_ECT0 =       0x01
QOF_ECT1 =       0x02
QOF_CE   =       0x04
QOF_TSOPT =      0x10
QOF_SACKOPT =    0x20
QOF_WSOPT =      0x40

Connection = collections.namedtuple("Connection",["client","port","state"])
Connection.OK = 0
Connection.FAILED = 1
Connection.TIMEOUT = 2

# HTTP constants
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0'

SpiderRecord = collections.namedtuple("SpiderRecord",
    ["ip","host","port","rport","ecnstate","connstate","httpstatus", "userval"])

FlowRecord = collections.namedtuple("FlowRecord",
    ["ip","port","octets","fif","fsf","fuf","fir","fsr","fur","ttl"])

MergedRecord = collections.namedtuple("MergedRecord",
    ["ip","host","port","rport","ecnstate","connstate","httpstatus", "userval",
     "octets","fif","fsf","fuf","fir","fsr","fur","ttl"])

Job = collections.namedtuple("Job", ["ip", "host", "rport", "userval"])

class EcnSpider2(qofspider.QofSpider):
    def __init__(self, result_sink,
                 worker_count, conn_timeout,
                 interface_uri,
                 local_ip4 = None, local_ip6 = None,
                 qof_port=4739,
                 check_interrupt=None):
        super().__init__(worker_count=worker_count, interface_uri=interface_uri, qof_port=qof_port, check_interrupt=check_interrupt)

        self.conn_timeout = conn_timeout
        self.result_sink = result_sink

        if sys.platform == 'linux':
            self.configurator_hooks = EcnSpider2ConfigLinux()
        elif sys.platform == 'darwin':
            self.configurator_hooks = EcnSpider2ConfigDarwin()
        else:
            raise NotImplemented("ECN configurator for your system {} is not implemented.".format(sys.platform))

        if local_ip4:
            self.local_ip4 = ip_address(local_ip4) if isinstance(local_ip4, str) else local_ip4
        else:
            self.local_ip4 = qofspider.local_address(ipv=4)

        if local_ip6:
            self.local_ip6 = ip_address(local_ip4) if isinstance(local_ip6, str) else local_ip6
        else:
            self.local_ip6 = qofspider.local_address(ipv=6)

    def config_one(self):
        self.configurator_hooks.config_one()

    def config_zero(self):
        self.configurator_hooks.config_zero()

    def connect(self, job, pcs, config):
        if job.ip.version == 4:
            sock = socket.socket()
        else:
            sock = socket.socket(socket.AF_INET6)

        try:
            sock.settimeout(self.conn_timeout)
            sock.connect((str(job.ip), job.rport))

            return Connection(sock, sock.getsockname()[1], Connection.OK)
        except TimeoutError:
            return Connection(sock, sock.getsockname()[1], Connection.TIMEOUT)
        except OSError as e:
            return Connection(sock, sock.getsockname()[1], Connection.FAILED)

    def post_connect(self, job, conn, pcs, config):
        if conn.state == Connection.OK:
            sr = SpiderRecord(job.ip, job.host, conn.port, job.rport, config, True, 0, job.userval)

        else:
            sr = SpiderRecord(job.ip, job.host, conn.port, job.rport, config, False, 0, job.userval)

        try:
            conn.client.shutdown(socket.SHUT_RDWR)
        except:
            pass

        try:
            conn.client.close()
        except:
            pass

        return sr

    def qof_config(self):
        return { 'template' : [
                 'flowStartMilliseconds',
                 'flowEndMilliseconds',
                 'octetDeltaCount',
                 'reverseOctetDeltaCount',
                 'packetDeltaCount',
                 'reversePacketDeltaCount',
                 'transportOctetDeltaCount',
                 'reverseTransportOctetDeltaCount',
                 'transportPacketDeltaCount',
                 'reverseTransportPacketDeltaCount',
                 'sourceIPv4Address',
                 'destinationIPv4Address',
                 'sourceIPv6Address',
                 'destinationIPv6Address',
                 'sourceTransportPort',
                 'destinationTransportPort',
                 'protocolIdentifier',
                 'initialTCPFlags',
                 'reverseInitialTCPFlags',
                 'unionTCPFlags',
                 'reverseUnionTCPFlags',
                 'lastSynTcpFlags',
                 'reverseLastSynTcpFlags',
                 'qofTcpCharacteristics',
                 'reverseQofTcpCharacteristics',
                 'minimumTTL',
                 'reverseMinimumTTL'],
                 'force-biflow': 1}

    def ignore_flow(self, flow):
        # Short-circuit non-TCP flows, and reset storms
        try:
            if flow["protocolIdentifier"] != 6:
                return True
            if flow["initialTCPFlags"] & TCP_RST:
                return True
        except:
            return True

        return False

    def tupleize_flow(self, flow):
        if self.ignore_flow(flow):
            return None

        # Short-circuit flows not from this source,
        # and select destination address based on version
        if ("sourceIPv4Address" in flow and
          flow["sourceIPv4Address"] == self.local_ip4):
            ip = flow["destinationIPv4Address"]
        elif ("sourceIPv6Address" in flow and
          flow["sourceIPv6Address"] == self.local_ip6):
            ip = flow["destinationIPv6Address"]
        else:
            return None

        # Merge flags
        fif = flow["initialTCPFlags"]
        fsf = (flow["lastSynTcpFlags"] |
              (flow["qofTcpCharacteristics"] & 0xFF00))
        fuf = (flow["unionTCPFlags"] |
              ((flow["qofTcpCharacteristics"] & 0xFF) << 8))

        fir = flow["reverseInitialTCPFlags"]
        fsr = (flow["reverseLastSynTcpFlags"] |
              (flow["reverseQofTcpCharacteristics"] & 0xFF00))
        fur = (flow["reverseUnionTCPFlags"] |
              ((flow["reverseQofTcpCharacteristics"] & 0xFF) << 8))

        ttl = flow["reverseMinimumTTL"]

        rtodc = flow["reverseTransportOctetDeltaCount"]

        # Export record
        return FlowRecord(ip,
                          flow["sourceTransportPort"],
                          rtodc,
                          fif, fsf, fuf, fir, fsr, fur, ttl)


    def merge(self, flow, res):
        self.result_sink(MergedRecord(res.ip, res.host, res.port, res.rport,
                res.ecnstate, res.connstate, res.httpstatus, res.userval,
                flow.octets, flow.fif, flow.fsf, flow.fuf,
                flow.fir, flow.fsr, flow.fur, flow.ttl))



class EcnSpider2Http(EcnSpider2):
    def __init__(self, result_sink,
                 worker_count, conn_timeout,
                 interface_uri,
                 local_ip4 = None, local_ip6 = None,
                 qof_port=4739,
                 check_interrupt=None):
        super().__init__(result_sink=result_sink, worker_count=worker_count, conn_timeout=conn_timeout,
                         interface_uri=interface_uri, local_ip4=local_ip4, local_ip6=local_ip6,
                         qof_port=qof_port, check_interrupt=check_interrupt)

    def connect(self, job, pcs, config):
        client = http.client.HTTPConnection(str(job.ip), timeout=self.conn_timeout)
        client.auto_open = 0
        try:
            client.connect()
        except socket.timeout:
            return Connection(None, None, Connection.TIMEOUT)
        except OSError as e:
            return Connection(None, None, Connection.FAILED)
        else:
            return Connection(client, client.sock.getsockname()[1], Connection.OK)

    def post_connect(self, job, conn, pcs, config):
        if conn.state == Connection.OK:
            headers = {'User-Agent': USER_AGENT,
                       'Connection': 'close',
                       'Host': job.host}
            try:
                conn.client.request('GET', '/', headers=headers)
                res = conn.client.getresponse()
                conn.client.close()

                return SpiderRecord(job.ip, job.host, conn.port, job.rport, config, True, res.status, None)
            except:
                return SpiderRecord(job.ip, job.host, conn.port, job.rport, config, True, 0, None)
            finally:
                conn.client.close()
        else:
            return SpiderRecord(job.ip, job.host, 0, job.rport, config, False, 0, None)

    def ignore_flow(self, flow):
        # Short-circuit non-HTTP over TCP flows, and reset storms
        try:
            if flow["protocolIdentifier"] != 6:
                return True
            if flow["destinationTransportPort"] != 80:
                return True
            if flow["initialTCPFlags"] & TCP_RST:
                return True
        except:
            return True

        return False

class EcnSpider2ConfigLinux:
    def __init__(self):
        pass

    def config_zero(self):
        subprocess.check_call(['sudo', '-n', '/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def config_one(self):
        subprocess.check_call(['sudo', '-n', '/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

class EcnSpider2ConfigDarwin:
    def __init__(self):
        pass

    def config_zero(self):
        subprocess.check_call(['sudo', '-n', '/usr/sbin/sysctl', '-w', 'net.inet.tcp.ecn_initiate_out=0'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def config_one(self):
        subprocess.check_call(['sudo', '-n', '/usr/sbin/sysctl', '-w', 'net.inet.tcp.ecn_initiate_out=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

