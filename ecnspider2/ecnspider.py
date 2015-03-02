"""
Ecnspider2: Qofspider-based tool for measuring ECN-linked connectivity
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

.. moduleauthor:: Brian Trammell <brian@trammell.ch>

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

import qofspider
import http.client
import collections

Connection = collections.namedtuple("Connection",["client","port","state"])
Connection.OK = 0
Connection.FAILED = 1
Connection.TIMEOUT = 2

SpiderResult = collections.namedtuple("SpiderResult",["ip","host","port","ecnstate","connstate","httpstatus"])

class EcnSpider2(QofSpider):
    def __init__(self, worker_count, conn_timeout, interface_uri, qof_port=4739):
        super().__init__(worker_count, interface_uri, qof_port)

        self.conn_timeout = conn_timeout

    def connect(self, job, pcs, config):
        client = http.client.HTTPConnection(job.ip, timeout=self.conn_imeout)
        client.auto_open = 0
        try:
            client.connect()
        except socket.timeout:
            return Connection(None, None, Connection.TIMEOUT)
        except OSError as e:
            return Connection(None, None, Connection.FAIL)
        else:
            return (client, client.sock.getsockname()[1], Connection.OK)

    def post_connect(self, job, conn, pcs, config):
        if conn.status == Connection.OK:
            headers = {'User-Agent': USER_AGENT, 
                       'Connection': 'close'
                       'Host': job.host}
            try:
                conn.client.request('GET', '/', headers=headers)
                res = conn.client.getresponse()
                conn.client.close()

                return SpiderResult(job.ip, job.host, conn.port, config, True, res.status)
            except:
                return SpiderResult(job.ip, job.host, conn.port, config, True, 0)
            finally:
                conn.client.close()
        else:
            return SpiderResult(job.ip, job.host, 0, config, False, 0)

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
                 'reverseQofTcpCharacteristics']}

    def tupleize_flow(self, flow):
        assert(False, "Cannot instantiate an abstract Qofspider")

    def merge(self, flow, res):
        assert(False, "Cannot instantiate an abstract Qofspider")


class EcnSpider2Linux(EcnSpider2):
    def __init__(self, worker_count, conn_timeout, interface_uri, qof_port=4739):
        super().__init__(worker_count, conn_timeout, interface_uri, qof_port)

    def config_zero(self):
        subprocess.check_call(['sudo', '-n', '/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'])

    def config_one(self):
        subprocess.check_call(['sudo', '-n', '/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'])

