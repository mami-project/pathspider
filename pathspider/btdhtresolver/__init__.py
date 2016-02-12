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
from datetime import datetime
import threading

def strbool(s):
    if s is None:
        return False
    if isinstance(s, bool):
        return s
    return s.lower() == "true" or s == "1" or s.lower() == "y" or s.lower() == "yes"

def services(ip4addr='0.0.0.0', ip6addr='::', port4='9881', port6='6882', enable_ipv6=True):
    """
    Return a list of mplane.scheduler.Service instances implementing 
    the mPlane capabilities for btdhtresolver.

    """
    servicelist = []
    servicelist.append(BtDhtSpiderService(btdhtspider_cap('ip4'), (ip4addr, int(port4))))
    if strbool(enable_ipv6):
        servicelist.append(BtDhtSpiderService(btdhtspider_cap('ip6'), (ip6addr, int(port6))))

    return servicelist


def btdhtspider_cap(ipv):
    cap = mplane.model.Capability(label='btdhtresolver-'+ipv, when='now ... future')

    cap.add_parameter("btdhtresolver.count")

    cap.add_result_column("source."+ipv)
    cap.add_result_column("source.port")
    cap.add_result_column("destination."+ipv)
    cap.add_result_column("destination.port")
    cap.add_result_column("btdhtresolver.nodeid")

    return cap

class BtDhtSpiderService(mplane.scheduler.Service):
    def __init__(self, cap, bindaddr):
        super().__init__(cap)

        self.ipv = 'ip4' if cap.has_result_column("source.ip4") else 'ip6'

        self.source_ip = ip_address(bindaddr[0])
        self.source_port = bindaddr[1]

        self.dht = torrent.BtDhtSpider(bindaddr=bindaddr, ip_version=self.ipv, unique=False)
        self.dht.start()

    def run(self, spec, check_interrupt):
        count = spec.get_parameter_value("btdhtresolver.count")

        starttime = datetime.utcnow()

        res = mplane.model.Result(specification=spec)

        checkcount = 0
        idx = 0
        unique = set()
        for addr in self.dht:
            # do not repeat addresses in result
            if addr not in unique:
                unique.add(addr)
                res.set_result_value("destination."+self.ipv, addr[0][0], idx)
                res.set_result_value("destination.port", addr[0][1], idx)
                res.set_result_value("btdhtresolver.nodeid", addr[1], idx)
                res.set_result_value("source."+self.ipv, self.source_ip, idx)
                res.set_result_value("source.port", self.source_port, idx)

                idx+=1
                if idx >= count:
                    break

            checkcount += 1
            if checkcount >= 200:
                checkcount = 0
                if check_interrupt():
                    break

        stoptime = datetime.utcnow()

        print("btdhtresolver: sending back {} addresses".format(idx))

        res.set_when(mplane.model.When(a=starttime, b=stoptime))

        return res


