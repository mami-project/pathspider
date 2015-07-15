"""
Ecnspider2: Qofspider-based tool for measuring ECN-linked connectivity
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

This module implements the mPlane component module interface for the ecnspider.py and
torrent.py modules.

    Copyright 2015 Elio Gubser <elio.gubser@alumni.ethz.ch>

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
from . import qofspider
from . import ecnspider
import collections

import os.path
import time
from datetime import datetime
import threading
import ipfix
import logging

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
scriptdir = os.path.dirname(os.path.abspath(__file__))
ipfix.ie.use_specfile(os.path.join(scriptdir, "qof.iespec"))

qofspider.log_to_console(logging.DEBUG)

def strbool(s):
    """
    interpret given parameter to a boolean value.
    bool() does not work here, because it returns true if not None.
    """
    if s is None:
        return False
    if isinstance(s, bool):
        return s
    elif isinstance(s, int):
        return s != 0
    elif isinstance(s, str):
        return s.lower() == "true" or s == "1" or s.lower() == "y" or s.lower() == "yes"
    else:
        return False

def services(ip4addr = None, ip6addr = None, worker_count = None, connection_timeout = None,
             interface_uri = None, qof_port=54739, enable_ipv6=True):
    """
    Return a list of mplane.scheduler.Service instances implementing 
    the mPlane capabilities for ecnspider.

    """

    if connection_timeout is None:
        connection_timeout = 15

    # global lock, only one ecnspider instance may run at a time.
    lock = threading.Lock()

    servicelist = []
    servicelist.append(EcnspiderService(ecnspider_cap(4), worker_count=worker_count, connection_timeout=connection_timeout, interface_uri=interface_uri, qof_port=qof_port, ip4addr=ip4addr, singleton_lock=lock))
    servicelist.append(EcnspiderHttpService(ecnspider_http_cap(4), worker_count=worker_count, connection_timeout=connection_timeout, interface_uri=interface_uri, qof_port=qof_port, ip4addr=ip4addr, singleton_lock=lock))
    if strbool(enable_ipv6):
        servicelist.append(EcnspiderService(ecnspider_cap(6), worker_count=worker_count, connection_timeout=connection_timeout, interface_uri=interface_uri, qof_port=qof_port, ip6addr=ip6addr, singleton_lock=lock))
        servicelist.append(EcnspiderHttpService(ecnspider_http_cap(6), worker_count=worker_count, connection_timeout=connection_timeout, interface_uri=interface_uri, qof_port=qof_port, ip4addr=ip4addr, singleton_lock=lock))
    
    return servicelist

def ecnspider_cap(ip_version):
    ipv = "ip"+str(ip_version)

    cap = mplane.model.Capability(label='ecnspider-'+ipv, when='now ... future')

    cap.add_parameter("destination."+ipv, "[*]")
    cap.add_parameter("destination.port", "[*]")

    cap.add_result_column("source.port")
    cap.add_result_column("destination."+ipv)
    cap.add_result_column("destination.port")
    cap.add_result_column("connectivity.ip")
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
    def __init__(self, cap, worker_count, connection_timeout, interface_uri, qof_port, singleton_lock, ip4addr = None, ip6addr = None):
        super().__init__(cap)

        self.worker_count = int(worker_count)
        self.connection_timeout = float(connection_timeout)
        self.interface_uri = interface_uri
        self.qof_port = int(qof_port)
        self.ip4addr = ip4addr
        self.ip6addr = ip6addr
        self.singleton_lock = singleton_lock

    def run(self, spec, check_interrupt):
        # try to acquire lock or immediately return error
        if not self.singleton_lock.acquire(blocking=False):
            raise Exception("An instance of ecnspider is already running.")

        try:
            # wrap the spec in a job source, either ipv4 or ipv6
            if spec.has_parameter("destination.ip4"):
                ips = spec.get_parameter_value("destination.ip4")
                ipv = "ip4"
            else:
                ips = spec.get_parameter_value("destination.ip6")
                ipv = "ip6"

            # setup ecnspider
            result_sink = collections.deque()
            ecn = ecnspider.EcnSpider2(result_sink.append,
                     worker_count=self.worker_count, conn_timeout=self.connection_timeout,
                     interface_uri=self.interface_uri,
                     local_ip4 = self.ip4addr, local_ip6 = self.ip6addr,
                     qof_port=self.qof_port, check_interrupt=check_interrupt)

            # formulate jobs
            ports = spec.get_parameter_value("destination.port")
            if len(ports) != len(ips):
                raise ValueError("destination.ip4/6, destination.port and torrentspider.nodeid don't have same amount of elements.")

            jobs = [ecnspider.Job(ip_address(ip), ip, port, None) for ip, port in zip(ips, ports)]
            for job in jobs:
                ecn.add_job(job)

            # run measurement
            starttime = datetime.utcnow()
            ecn.run()
            ecn.stop()
            if ecn.exception is not None:
                raise ecn.exception
            stoptime = datetime.utcnow()

            res = mplane.model.Result(specification=spec)
            res.set_when(mplane.model.When(a=starttime, b=stoptime))

            for i, result in enumerate(result_sink):
                res.set_result_value("source.port",                 result.port, i)
                res.set_result_value("destination."+ipv,            result.ip, i)
                res.set_result_value("destination.port",            result.rport, i)
                res.set_result_value("connectivity.ip",             result.connstate, i)
                res.set_result_value("ecnspider.ecnstate",          result.ecnstate, i)
                res.set_result_value("ecnspider.initflags.fwd",     result.fif, i)
                res.set_result_value("ecnspider.synflags.fwd",      result.fsf, i)
                res.set_result_value("ecnspider.unionflags.fwd",    result.fuf, i)
                res.set_result_value("ecnspider.initflags.rev",     result.fir, i)
                res.set_result_value("ecnspider.synflags.rev",      result.fsr, i)
                res.set_result_value("ecnspider.unionflags.rev",    result.fur, i)
                res.set_result_value("ecnspider.ttl.rev.min",       result.ttl, i)
            print("ecnspider2: returning {} records".format(len(result_sink)))
        except Exception as e:
            self.singleton_lock.release()
            raise e
        else:
            self.singleton_lock.release()
            return res

def ecnspider_http_cap(ip_version):
    ipv = "ip"+str(ip_version)

    cap = mplane.model.Capability(label='ecnspider-http-'+ipv, when='now ... future')

    cap.add_parameter("destination."+ipv, "[*]")
    cap.add_parameter("destination.port", "[*]")
    cap.add_parameter("ecnspider.hostname", "[*]")

    cap.add_result_column("source.port")
    cap.add_result_column("destination."+ipv)
    cap.add_result_column("destination.port")
    cap.add_result_column("ecnspider.hostname")
    cap.add_result_column("connectivity.ip")
    cap.add_result_column("ecnspider.httpstatus")
    cap.add_result_column("ecnspider.ecnstate")
    cap.add_result_column("ecnspider.initflags.fwd")
    cap.add_result_column("ecnspider.synflags.fwd")
    cap.add_result_column("ecnspider.unionflags.fwd")
    cap.add_result_column("ecnspider.initflags.rev")
    cap.add_result_column("ecnspider.synflags.rev")
    cap.add_result_column("ecnspider.unionflags.rev")
    cap.add_result_column("ecnspider.ttl.rev.min")

    return cap

class EcnspiderHttpService(mplane.scheduler.Service):
    def __init__(self, cap, worker_count, connection_timeout, interface_uri, qof_port, singleton_lock, ip4addr = None, ip6addr = None):
        super().__init__(cap)

        self.worker_count = int(worker_count)
        self.connection_timeout = float(connection_timeout)
        self.interface_uri = interface_uri
        self.qof_port = int(qof_port)
        self.ip4addr = ip4addr
        self.ip6addr = ip6addr
        self.singleton_lock = singleton_lock

    def run(self, spec, check_interrupt):
        # try to acquire lock or immediately return error
        if not self.singleton_lock.acquire(blocking=False):
            raise Exception("An instance of ecnspider is already running.")

        try:
            # wrap the spec in a job source, either ipv4 or ipv6
            if spec.has_parameter("destination.ip4"):
                ips = spec.get_parameter_value("destination.ip4")
                ipv = "ip4"
            else:
                ips = spec.get_parameter_value("destination.ip6")
                ipv = "ip6"

            # setup ecnspider
            result_sink = collections.deque()
            ecn = ecnspider.EcnSpider2Http(result_sink.append,
                     worker_count=self.worker_count, conn_timeout=self.connection_timeout,
                     interface_uri=self.interface_uri,
                     local_ip4 = self.ip4addr, local_ip6 = self.ip6addr,
                     qof_port=self.qof_port, check_interrupt=check_interrupt)

            # formulate jobs
            ports = spec.get_parameter_value("destination.port")
            if len(ports) != len(ips):
                raise ValueError("destination.ip4/6 and destination.port don't have same amount of elements.")

            hosts = spec.get_parameter_value("ecnspider.hostname")
            if len(hosts) != len(ips):
                raise ValueError("ecnspider.hostname and destination.ip4/6 don't have same amount of elements.")

            jobs = [ecnspider.Job(ip_address(ip), host, port, None) for ip, port, host in zip(ips, ports, hosts)]
            for job in jobs:
                ecn.add_job(job)

            # run measurement
            starttime = datetime.utcnow()
            ecn.run()
            ecn.stop()
            if ecn.exception is not None:
                raise ecn.exception
            stoptime = datetime.utcnow()

            res = mplane.model.Result(specification=spec)
            res.set_when(mplane.model.When(a=starttime, b=stoptime))

            for i, result in enumerate(result_sink):
                res.set_result_value("source.port",                 result.port, i)
                res.set_result_value("destination."+ipv,            result.ip, i)
                res.set_result_value("destination.port",            result.rport, i)
                res.set_result_value("connectivity.ip",             result.connstate, i)
                res.set_result_value("ecnspider.hostname",          result.host)
                res.set_result_value("ecnspider.ecnstate",          result.ecnstate, i)
                res.set_result_value("ecnspider.httpstatus",        result.httpstatus)
                res.set_result_value("ecnspider.initflags.fwd",     result.fif, i)
                res.set_result_value("ecnspider.synflags.fwd",      result.fsf, i)
                res.set_result_value("ecnspider.unionflags.fwd",    result.fuf, i)
                res.set_result_value("ecnspider.initflags.rev",     result.fir, i)
                res.set_result_value("ecnspider.synflags.rev",      result.fsr, i)
                res.set_result_value("ecnspider.unionflags.rev",    result.fur, i)
                res.set_result_value("ecnspider.ttl.rev.min",       result.ttl, i)

            print("ecnspider2: returning {} records".format(len(result_sink)))
        except Exception as e:
            self.singleton_lock.release()
            raise e
        else:
            self.singleton_lock.release()
            return res

