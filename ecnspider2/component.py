'''
ECN-Spider: Large-scale ECN connectivity probe for mPlane

This module implements the mPlane component module interface and 
wraps a modified the ecn_spider.py and resolution.py modules of
ECN-Spider to allow remote control of ECN-Spider instances via 
client-initiated mPlane connections.

    Copyright 2015 Brian Trammell <brian@trammell.ch>
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

'''

def services():
    """
    Return a list of mplane.scheduler.Service instances implementing 
    the mPlane capabilities for ecnspider.

    """
    pass

def spider_cap(src_address):
    ipv = "ip"+str(src_address.version)

    cap = mplane.model.Capability(label="ecnspider-"+ipv)
    cap.add_parameter("source."+ipv,ipaddr)
    cap.add_parameter("destination."+ipv,"[*]")
    cap.add_result_column("destination."+ipv)
    cap.add_result_column("ecnspider.ecnstate")
    cap.add_result_column("connectivity.ip")
    cap.add_result_column("octets.layer5")
    cap.add_result_column("ecnspider.initflags.fwd")
    cap.add_result_column("ecnspider.synflags.fwd")
    cap.add_result_column("ecnspider.unionflags.fwd")
    cap.add_result_column("ecnspider.initflags.rev")
    cap.add_result_column("ecnspider.synflags.rev")
    cap.add_result_column("ecnspider.unionflags.rev")

def resolver_cap(src_address):
    ipv = "ip"+str(src_address.version)
    cap = mplane.model.Capability(label="ecnspider-resolver-"+ipv)
    cap.add_parameter("source."+ipv,ipaddr)
    cap.add_parameter("destination.url","[*]")
    cap.add_result_column("destination.url")
    cap.add_result_column("destination.ip4")
    cap.add_result_column("destination.ip6")

class SpiderService(mplane.scheduler.Service):
    def __init__(self, cap):
        super().__init__(cap)

        # capability assertions
        assert cap.has_parameter("source.ip4") or \
                cap.has_parameter("source.ip6")
        assert cap.has_parameter("destination.ip4") or \
                cap.has_parameter("destination.ip6")
        assert cap.has_parameter("destination.url")
        assert cap.has_parameter("destination.alexarank")

    def run(self, spec, check_interrupt):
        # wrap the spec in a job source

        # wrap the result in a result sink

        # create a spider

        # watch it go!
        pass

class ResolutionService(mplane.scheduler.Service):
    pass