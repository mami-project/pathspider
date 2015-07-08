"""
webresolver: Resolve a large number of domains to IPv4 and IPv6 addresses.
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

This module implements the mPlane component module interface for webresolver.

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

import os.path
from datetime import datetime
import threading
import ipfix

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
scriptdir = os.path.dirname(os.path.abspath(__file__))
ipfix.ie.use_specfile(os.path.join(scriptdir, "qof.iespec"))

def services(ip4addr = None, ip6addr = None):
    """
    Return a list of mplane.scheduler.Service instances implementing
    the mPlane capabilities for webresolver.

    """

    servicelist = []

    servicelist.append(WebresolverService(webresolver_cap(ip_address(ip4addr or '0.0.0.0')), 'ip4'))
    servicelist.append(WebresolverService(webresolver_cap(ip_address(ip6addr or '::')), 'ip6'))

    return servicelist


def webresolver_cap(ipaddr, reguri):
    ipv = "ip"+str(ipaddr.version)

    cap = mplane.model.Capability(label='webresolver-'+ipv, when='now ... future', registry_uri=reguri)

    cap.add_parameter("ecnspider.hostname")
    cap.add_parameter("destination.port")

    cap.add_result_column("destination."+ipv)
    cap.add_result_column("destination.port")
    cap.add_result_column("ecnspider.hostname")

    return cap

class WebresolverService(mplane.scheduler.Service):
    def __init__(self, cap, ipv):
        super().__init__(cap)
        self.ipv = ipv

    def run(self, spec, check_interrupt):

        starttime = datetime.utcnow()

        res = mplane.model.Result(specification=spec)

        hostnames = spec.get_parameter_value("ecnspider.hostname")
        ports = spec.get_parameter_value("destination.port")

        for hostname, port in zip(hostnames, ports):
            res.set_result_value("destination."+self.ipv, addr[0][0], idx)
            res.set_result_value("destination.port", addr[0][1], idx)
            res.set_result_value("ecnspider.hostname", addr[1], idx)

        stoptime = datetime.utcnow()

        res.set_when(mplane.model.When(a=starttime, b=stoptime))

        return res


