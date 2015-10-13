"""
Ecnspider2: Qofspider-based tool for measuring ECN-linked connectivity
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

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

import mplane
import mplane.tls
import mplane.utils
import mplane.client
import time
import collections
import threading
import pandas as pd
import logging
from ipaddress import ip_address
from . import resolver
from . import ecnclient
from . import tbclient


QUEUE_SLEEP = 2

class NotFinishedException(Exception):
    pass

class PathSpiderClient:
    # queued chunks - in queue to be sent to ecnspider component, feeder thread loads addresses
    # pending chunks - currently processing
    # finished chunks - finished, interrupted chunks or chunks which encountered an exception, consumer thread takes finished chunks and do further investigation

    def __init__(self, count, tls_state, probes, resolver, chunk_size = 1000, ipv='ip4'):
        self.count = count
        self.chunk_size = chunk_size
        self.ipv = ipv
        self.probes = probes

        self.resolver_doit = False
        self.resolver_pending = False
        self.resolver = resolver

        self.ecn_results = ecnclient.EcnAnalysis()
        self.tb_results = {}

        self.subjects = []
        self.subjects_map = {}

        self.ecn_client = ecnclient.EcnClient(self.ecn_result_sink, tls_state, self.probes, ipv)
        self.tb_client = tbclient.TbClient(self.tb_result_sink, tls_state, self.probes, ipv)

        self.next_chunk_id = 0
        self.running = True
        self.thread = threading.Thread(name='client', target=self.func)
        self.thread.start()

    def status(self):
        return {
            'probes': [name for name, _ in self.probes],
            'resolver': {'pending': self.resolver_pending},
            'ecnclient': self.ecn_client.status(),
            'tbclient': self.tb_client.status()
        }

    def resolve_one(self):
        self.resolver_doit = True

    def func(self):
        logger = logging.getLogger("client")
        logger.info("Started.")
        while self.running:
            #if self.ecn_client.queue_size() < 3:
            if self.resolver_doit is True:
                logger.info("Request to resolve {} addresses.".format(self.chunk_size))
                self.resolver_pending = True
                addrs = self.resolver.request(self.chunk_size)
                self.resolver_pending = False

                if addrs is None:
                    logger.error("Something went wrong when requesting addresses. Trying again..")
                    time.sleep(1)
                    continue

                if len(addrs) == 0:
                    logger.info("No more addresses available.")
                    self.resolver_doit = False
                    break

                logger.info("Received {} IPs".format(len(addrs)))

                chunk_id = self.next_chunk_id

                # create subjects
                for addr in addrs:
                    subject = {'ip': str(addr.ip), 'port': addr.port, 'chunk_id': chunk_id}
                    self.subjects_map[str(addr.ip)] = subject
                    self.subjects.append(subject)

                self.next_chunk_id+=1
                self.ecn_client.add_job(addrs, chunk_id, self.ipv, self.resolver.flavor)

                self.resolver_doit = False

            time.sleep(1)

    def ecn_result_sink(self, analysis:ecnclient.EcnAnalysis, chunk_id:int):
        """
        Append results and order tracebox analysis on IPs in 'other'
        """
        self.ecn_results += analysis

        # update subject info
        for ip, result in analysis.get_ip_and_result():
            self.subjects_map[str(ip)]['ecnresult'] = result

        """
        if len(analysis.other) > 0:
            print("Adding {} ips to tracebox queue".format(len(analysis.other)))
            for ip, port in zip(analysis.other['destination.'+self.ipv], analysis.other['destination.port']):
                self.tb_client.add_job(ip, port)

        if len(self.ecn_results) >= self.count:
            print("Got enough ecn result, pausing ecnclient execution")
            self.ecn_client.pause()
        """

    def trace(self, ip):
        sub = self.subjects_map[ip]
        sub['tbresult'] = None
        self.tb_client.add_job(sub['ip'], sub['port'])

    def tb_result_sink(self, ip, trace):
        self.subjects_map[str(ip)]['tbresult'] = trace
        self.tb_results[str(ip)] = trace

    def shutdown(self):
        logger = logging.getLogger("client")
        logger.info("Attempting shutdown...")

        self.running = False
        self.ecn_client.shutdown()
        self.tb_client.shutdown()

        logger.info("Shutdown complete.")