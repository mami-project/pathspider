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
from . import torrent
import collections

import os.path
import time
from datetime import datetime
import threading
import ipfix

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
scriptdir = os.path.dirname(os.path.abspath(__file__))
ipfix.ie.use_specfile(os.path.join(scriptdir, "qof.iespec"))

def services(ip4addr = None, ip6addr = None, worker_count = None, connection_timeout = None, interface_uri = None, qof_port=54739,
            btdhtport4 = 9881, btdhtport6 = 9882):
    """
    Return a list of mplane.scheduler.Service instances implementing 
    the mPlane capabilities for btdhtresolver.

    """

    # global lock, only one btdhtresolver instance may run at a time.
    lock = threading.Lock()

    servicelist = []

    servicelist.append(BtDhtSpiderService(btdhtspider_cap(ip_address(ip4addr or '0.0.0.0'), btdhtport4)))

    servicelist.append(BtDhtSpiderService(btdhtspider_cap(ip_address(ip6addr or '::'), btdhtport6)))

    return servicelist


def btdhtspider_cap(ipaddr, port):
    ipv = "ip"+str(ipaddr.version)

    cap = mplane.model.Capability(label='btdhtspider-'+ipv, when='now ... future')

    cap.add_metadata("source."+ipv, ipaddr)
    cap.add_metadata("source.port", port)

    cap.add_parameter("btdhtspider.count")
    cap.add_parameter("btdhtspider.unique")

    cap.add_result_column("destination."+ipv)
    cap.add_result_column("destination.port")
    cap.add_result_column("btdhtspider.nodeid")

    return cap

class BtDhtSpiderService(mplane.scheduler.Service):
    def __init__(self, cap):
        super().__init__(cap)

        if cap.has_metadata("source.ip4"):
            bindaddr = (str(cap.get_metadata_value("source.ip4")), cap.get_metadata_value("source.port"))
            ip_version = 4
            self.ipv = "ip4"
        else:
            bindaddr = (str(cap.get_metadata_value("source.ip6")), cap.get_metadata_value("source.port"))
            ip_version = 6
            self.ipv = "ip6"

        self.dht = torrent.BtDhtSpider(bindaddr=bindaddr, ip_version=ip_version, unique=False)
        self.dht.start()

    def run(self, spec, check_interrupt):
        count = spec.get_parameter_value("btdhtspider.count")
        if spec.has_parameter("btdhtspider.unique"):
            unique = spec.get_parameter_value("btdhtspider.unique")
        else:
            unique = False

        starttime = datetime.utcnow()

        res = mplane.model.Result(specification=spec)

        ipset = set()
        checkcount = 0
        result_idx = 0
        for addr in self.dht:
            if not unique or addr[0][0] not in ipset:
                ipset.add(addr[0][0])

                res.set_result_value("destination."+self.ipv, addr[0][0], result_idx)
                res.set_result_value("destination.port", addr[0][1], result_idx)
                res.set_result_value("btdhtspider.nodeid", addr[1], result_idx)

                result_idx += 1

            if result_idx >= count:
                break

            checkcount += 1
            if checkcount >= 200:
                checkcount = 0
                if check_interrupt():
                    break


        stoptime = datetime.utcnow()

        res.set_when(mplane.model.When(a=starttime, b=stoptime))

        return res


