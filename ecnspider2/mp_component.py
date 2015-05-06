"""
ECN-Spider: Large-scale ECN connectivity probe for mPlane

This module implements the mPlane component module interface and 
wraps a modified the ecn_spider.py and resolution.py modules of
ECN-Spider to allow remote control of ECN-Spider instances via 
client-initiated mPlane connections.

    Copyright 2015 Elio Gubser <elio.gubser@alumni.ethz.ch>
    ECN-Spider core Copyright 2014 Damiano Boppart

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

import mplane
from . import ecnspider
import collections

import os.path
from datetime import datetime


scriptdir = os.path.dirname(os.path.abspath(__file__))
reguri = os.path.join(scriptdir, "ecnregistry.json")
mplane.model.initialize_registry(reguri)

ecnspider.log_to_console('DEBUG')

def services(ip4addr = None, ip6addr = None, worker_count = None, connection_timeout = None, interface_uri = None, qof_port=None):
    """
    Return a list of mplane.scheduler.Service instances implementing 
    the mPlane capabilities for ecnspider.

    """
    servicelist = []
    if ip4addr is not None:
        servicelist.append(EcnspiderService(ecnspider_torrent_cap(ip_address(ip4addr)), worker_count=worker_count, connection_timeout=connection_timeout, interface_uri=interface_uri, qof_port=qof_port))
        #servicelist.append(torrentspider_cap(ip4addr))
    if ip6addr is not None:
        servicelist.append(EcnspiderService(ecnspider_torrent_cap(ip_address(ip6addr)), worker_count=worker_count, connection_timeout=connection_timeout, interface_uri=interface_uri, qof_port=qof_port))
        #servicelist.append(torrentspider_cap(ip6addr))

    return servicelist

def ecnspider_torrent_cap(src_address):
    ipv = "ip"+str(src_address.version)


    """
    dictval = {
        'capability':mplane.model.VERB_MEASURE,
        'registry': os.path.join(scriptdir, "ecnregistry.json"),
        'label': 'ecnspider',
        'when': 'now + inf ... future'
    }"""


    cap = mplane.model.Capability(label='ecnspider', when='now ... future', reguri=reguri)

    cap.add_parameter("source."+ipv, src_address)
    cap.add_parameter("list.destination."+ipv, "[*]")
    cap.add_parameter("list.destination.port", "[*]")
    cap.add_parameter("btdhtspider.nodeid", "[*]")

    cap.add_result_column("source.port")
    cap.add_result_column("destination."+ipv)
    cap.add_result_column("destination.port")
    cap.add_result_column("connectivity.ip")
    cap.add_result_column("btdhtspider.nodeid")
    cap.add_result_column("ecnspider.ecnstate")
    cap.add_result_column("ecnspider.initflags.fwd")
    cap.add_result_column("ecnspider.synflags.fwd")
    cap.add_result_column("ecnspider.unionflags.fwd")
    cap.add_result_column("ecnspider.initflags.rev")
    cap.add_result_column("ecnspider.synflags.rev")
    cap.add_result_column("ecnspider.unionflags.rev")
    cap.add_result_column("ecnspider.ttl.rev.min")

    return cap

class EcnspiderService(mplane.scheduler.Service):
    def __init__(self, cap, worker_count, connection_timeout, interface_uri, qof_port, ip4addr = None, ip6addr = None,):
        super().__init__(cap)

        self.worker_count = int(worker_count)
        self.connection_timeout = float(connection_timeout)
        self.interface_uri = interface_uri
        self.qof_port = int(qof_port)
        self.ip4addr = ip4addr
        self.ip6addr = ip6addr

    def run(self, spec, check_interrupt):
        local_ip4 = spec.get_parameter_value("source.ip4") if spec.has_parameter("source.ip4") else None
        local_ip6 = spec.get_parameter_value("source.ip6") if spec.has_parameter("source.ip6") else None

        # wrap the spec in a job source, either ipv4 or ipv6
        if spec.has_parameter("list.destination.ip4"):
            ips = spec.get_parameter_value("list.destination.ip4")
            ipv = "ip4"
        elif spec.has_parameter("list.destination.ip6"):
            ips = spec.get_parameter_value("list.destination.ip6")
            ipv = "ip6"
        else:
            raise ValueError("No destination IPs specified.")

        # setup ecnspider
        result_sink = collections.deque()
        ecn = ecnspider.EcnSpider2(result_sink.append,
                 worker_count=self.worker_count, conn_timeout=self.connection_timeout,
                 interface_uri=self.interface_uri,
                 local_ip4 = local_ip4, local_ip6 = local_ip6,
                 qof_port=self.qof_port)

        # formulate jobs
        ports = spec.get_parameter_value("list.destination.port")
        nodeids = spec.get_parameter_value("btdhtspider.nodeid")
        if len(ports) != len(ips):
            raise ValueError("list.destination.ip4/6, list.destination.port and torrentspider.nodeid don't have same amount of elements.")

        jobs = [ecnspider.Job(ip_address(ip), ip, port, nodeid) for ip, port, nodeid in zip(ips, ports, nodeids)]
        for job in jobs:
            ecn.add_job(job)

        # run measurement
        starttime = datetime.utcnow()
        ecn.run()
        ecn.stop()
        stoptime = datetime.utcnow()

        res = mplane.model.Result(specification=spec)
        res.set_when(mplane.model.When(a=starttime, b=stoptime))

        for i, result in enumerate(result_sink):
            res.set_result_value("source.port",                 result.port, i)
            res.set_result_value("destination."+ipv,            result.ip, i)
            res.set_result_value("destination.port",            result.rport, i)
            res.set_result_value("btdhtspider.nodeid",          result.nodeid, i)
            res.set_result_value("connectivity.ip",             result.connstate, i)
            res.set_result_value("ecnspider.ecnstate",          result.ecnstate, i)
            res.set_result_value("ecnspider.initflags.fwd",     result.fif, i)
            res.set_result_value("ecnspider.synflags.fwd",      result.fsf, i)
            res.set_result_value("ecnspider.unionflags.fwd",    result.fuf, i)
            res.set_result_value("ecnspider.initflags.rev",     result.fir, i)
            res.set_result_value("ecnspider.synflags.rev",      result.fsr, i)
            res.set_result_value("ecnspider.unionflags.rev",    result.fur, i)
            res.set_result_value("ecnspider.ttl.rev",           result.ttl, i)

        res.set_result_value("source.port", 80)
        return res

class ResolutionService(mplane.scheduler.Service):
    pass
