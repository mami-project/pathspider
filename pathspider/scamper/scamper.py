# mPlane Protocol Reference Implementation
# scamper probe component code
#
# (c) 2013-2014 mPlane Consortium (http://www.ict-mplane.eu)
#               Author: Korian Edeline <korian.edeline@ulg.ac.be>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Implements Tracebox for integration into
the mPlane reference implementation.

contains:
    -  ping                            OK
    -  trace                           OK
    -  tracelb                         OK
    -  tracebox                        OK

"""

import re, collections, subprocess
import random, subprocess
from datetime import datetime, timedelta
import argparse
import json

import mplane.model
import mplane.scheduler
import mplane.utils

# DEFAULTS

DEFAULT_IP4_NET = "192.168.1.0/24"
DEFAULT_SUPERVISOR_IP4 = '127.0.0.1'
DEFAULT_SUPERVISOR_PORT = 8888

LOOP4 = "127.0.0.1"
LOOP6 = "::1"

MIN_SPORT = 1024
MAX_SPORT = 65535

def _random_sport():
   return random.randint(MIN_SPORT,MAX_SPORT)

###############################################################################
#################################  ARGUMENTS  #################################
###############################################################################

_scampercmd  = ["sudo", "scamper", "-c"]
_scamper_dip = "-i"

_traceboxcmd    = _scampercmd + ["tracebox"]
_traceboxopt_v6 = "-6"

_traceboxopt_udp   = "-u"
_traceboxopt_dport = "-d"
_traceboxopt_probe = "-p"
_traceboxopt_ipl   = "-t" # icmp payload length

_pingcmd = _scampercmd + ["ping"]
_pingopt_period   = "-i" # -
_pingopt_payload  = "-B"
_pingopt_count    = "-c" # -
_pingopt_icmp_sum = "-C"
_pingopt_dport    = "-d"
_pingopt_sport    = "-F" # default
_pingopt_ttl      = "-m" # default 64
_pingopt_rcount   = "-o" # default all == 0
_pingopt_pattern  = "-p" # default 0
_pingopt_method   = "-P" # default icmp-echo
_pingopt_RR       = "-R"
_pingopt_size     = "-s" # default v4:84 v6:56
_pingopt_source   = "-S" # -
_pingopt_tos      = "-z" # default 0x0

_tracecmd = _scampercmd + ["trace"]

_traceopt_confidence = "-c"
_traceopt_dport      = "-d"
_traceopt_firsthop   = "-f"
_traceopt_gaplimit   = "-g"
_traceopt_gapaction  = "-G"
_traceopt_maxttl     = "-m"
_traceopt_M          = "-M"
_traceopt_loops      = "-l"
_traceopt_loopaction = "-L"
_traceopt_payload    = "-p"
_traceopt_method     = "-P"
_traceopt_attempts   = "-q"
_traceopt_Q          = "-Q"
_traceopt_sport      = "-s"
_traceopt_srcaddr    = "-S"
_traceopt_tos        = "-t"
_traceopt_T          = "-T"
_traceopt_wait       = "-w"
_traceopt_waitprobe  = "-W"
_traceopt_gssentry   = "-z"
_traceopt_lssname    = "-Z"

_dealiascmd = _scampercmd + ["dealias"]

_dealiasopt_dport       = "-d"
_dealiasopt_fudge       = "-f"
_dealiasopt_method      = "-m"
_dealiasopt_replyc      = "-o"
_dealiasopt_option      = "-O"
_dealiasopt_probedef    = "-p"
_dealiasopt_attempts    = "-q"
_dealiasopt_waitround   = "-r"
_dealiasopt_sport       = "-s"
_dealiasopt_t           = "-t"
_dealiasopt_waittimeout = "-w"
_dealiasopt_waitprobe   = "-W"
_dealiasopt_exclude     = "-x"

_neighbourdisccmd = _scampercmd + ["neighbourdisc"]

_neighbourdiscopt_F          = "-F"
_neighbourdiscopt_Q          = "-Q"
_neighbourdiscopt_interface  = "-i"
_neighbourdiscopt_replyc     = "-o"
_neighbourdiscopt_attempts   = "-q"
_neighbourdiscopt_wait       = "-w"

_tracelbcmd = _scampercmd + ["tracelb"]

_tracelbopt_confidence  = "-c"
_tracelbopt_dport       = "-d"
_tracelbopt_firsthop    = "-f"
_tracelbopt_gaplimit    = "-g"
_tracelbopt_method      = "-P"
_tracelbopt_attempts    = "-q"
_tracelbopt_maxprobec   = "-Q"
_tracelbopt_sport       = "-s"
_tracelbopt_tos         = "-t"
_tracelbopt_waittimeout = "-w"
_tracelbopt_waitprobe   = "-W"

_stingcmd = _scampercmd + ["sting"]

_stingopt_count        = "-c"
_stingopt_dport        = "-d"
_stingopt_distribution = "-f"
_stingopt_request      = "-h"
_stingopt_hole         = "-H"
_stingopt_inter        = "-i"
_stingopt_mean         = "-m"
_stingopt_sport        = "-s"

_tbitcmd = _scampercmd + ["tbit"]

_tbitopt_type      = "-t"
_tbitopt_app       = "-p"
_tbitopt_dport     = "-d"
_tbitopt_sport     = "-s"
_tbitopt_mss       = "-m"
_tbitopt_mtu       = "-M"
_tbitopt_option    = "-O"
_tbitopt_ptbsrc    = "-P"
_tbitopt_srcaddr   = "-s"
_tbitopt_url       = "-u"


###############################################################################
#################################  PARSING  ###################################
###############################################################################

TraceboxValue = collections.namedtuple("TraceboxValue", ["addr", "modifs", "payload_len"])

def _detail_ipl(ipl):
    """
    return a detailed string
    """
    ipls = {"(full)": "Full packet", "(8B)" : "Layer 3 Header + First 8 L3 payload bytes", "(L3)" : "Layer 3 header", "(0)" : "Empty"}
    return ipls[ipl] if ipl in ipls else ipl

_pingline_re = re.compile("seq=(\d+)\s+\S+=(\d+)\s+time=([\d\.]+)\s+ms")

PingValue = collections.namedtuple("PingValue", ["time", "seq", "ttl", "usec"])

def _parse_ping_line(line):
    m = _pingline_re.search(line)
    if m is None:
        print(line)
        return None
    mg = m.groups()
    return PingValue(datetime.utcnow(), int(mg[0]), int(mg[1]), int(float(mg[2]) * 1000))

TraceValue = collections.namedtuple("TraceValue", ["addr", "rtt"])

def _parse_trace(tb_output):
    """
    returns list of tuple (intermediate.addr, intermediate.modifs)
    """
    tuples=[]

    for line in tb_output[2:]:
        pline=line.split()
        if len(pline)==4:
            tuples.append(TraceValue(pline[1], pline[2]))
        else:
            tuples.append(TraceValue("*", "NaN"))
    return tuples

###############################################################################
#################################  PROCESS  ###################################
###############################################################################


def _tracebox_process(sipaddr, dipaddr, v, udp=None, dport=None, probe=None, get_icmp_payload_len=None):
    tracebox_argv = list(_traceboxcmd)

    if v is 6:
        tracebox_argv[-1] += " "+_traceboxopt_v6
    if udp is not None and udp is not "0":
        tracebox_argv[-1] += " "+_traceboxopt_udp
    if get_icmp_payload_len is not None:
        tracebox_argv[-1] += " "+_traceboxopt_ipl
    if dport is not None:
        tracebox_argv[-1] += " "+_traceboxopt_dport+" "+str(dport)
    if probe is not None and udp is not "":
        tracebox_argv[-1] += " "+_traceboxopt_probe+" "+str(probe)

    tracebox_argv += [_scamper_dip, str(dipaddr)]

    print("running " + " ".join(tracebox_argv))
    return subprocess.Popen(tracebox_argv, stdout=subprocess.PIPE)

def _tracebox4_process(sipaddr, dipaddr, v=4, udp=None, dport=None, probe=None, get_icmp_payload_len=None):
    return _tracebox_process(sipaddr, dipaddr, v, udp, dport, probe, get_icmp_payload_len)

def _tracebox6_process(sipaddr, dipaddr, v=6, udp=None, dport=None, probe=None, get_icmp_payload_len=None):
    return _tracebox_process(sipaddr, dipaddr, v, udp, dport, probe, get_icmp_payload_len)

def _ping_process(sipaddr, dipaddr, period, count, payload=None, chksum=None, dport=None, sport=None, ttl=None, pattern=None, method=None, rr=None, size=None, tos=None, rcount=None):
    ping_argv = list(_pingcmd)
    if period is not None:
        ping_argv[-1] += " "+_pingopt_period+" "+str(period)
    if count is not None:
        ping_argv[-1] += " "+_pingopt_count+" "+str(count)
    if payload is not None and payload is not "":
        ping_argv[-1] += " "+_pingopt_payload+" "+str(payload)
    if chksum is not None and chksum is not "":
        ping_argv[-1] += " "+_pingopt_icmp_sum+" "+str(chksum)
    if dport is not None and dport != -1:
        ping_argv[-1] += " "+_pingopt_dport+" "+str(dport)
    if sport is not None and sport != -1:
        ping_argv[-1] += " "+_pingopt_sport+" "+str(sport)
    if ttl is not None and ttl != -1:
        ping_argv[-1] += " "+_pingopt_ttl+" "+str(ttl)
    if rcount is not None and rcount != -1:
        ping_argv[-1] += " "+_pingopt_rcount+" "+str(rcount)
    if pattern is not None and pattern is not "":
        ping_argv[-1] += " "+_pingopt_pattern+" "+str(pattern)
    if method is not None and method is not "":
        ping_argv[-1] += " "+_pingopt_method+" "+str(method)
    if rr:
        ping_argv[-1] += " "+_pingopt_RR
    if size is not None:
        ping_argv[-1] += " "+_pingopt_size+" "+str(size)
    if tos is not None:
        ping_argv[-1] += " "+_pingopt_tos+" "+str(tos)

    ping_argv[-1] += " "+_pingopt_source+" "+str(sipaddr)

    ping_argv += [_scamper_dip, str(dipaddr)]

    print("running " + " ".join(ping_argv))

    return subprocess.Popen(ping_argv, stdout=subprocess.PIPE)

def _ping4_process(sipaddr, dipaddr, period=None, count=None):
    return _ping_process(sipaddr, dipaddr, period, count)

def _ping6_process(sipaddr, dipaddr, period=None, count=None):
    return _ping_process(sipaddr, dipaddr, period, count)

def pings_min_delay(pings):
    return min(map(lambda x: x.usec, pings))

def pings_mean_delay(pings):
    return int(sum(map(lambda x: x.usec, pings)) / len(pings))

def pings_median_delay(pings):
    return sorted(map(lambda x: x.usec, pings))[int(len(pings) / 2)]

def pings_max_delay(pings):
    return max(map(lambda x: x.usec, pings))

def pings_start_time(pings):
    return pings[0].time

def pings_end_time(pings):
    return pings[-1].time

def _trace_process(sipaddr, dipaddr, confidence, dport, firsthop, gaplimit, gapaction, maxttl, M, loops, loopaction, payload, method, attempts, Q, sport, srcaddr, tos, T, wait, waitprobe, lssname):
    trace_argv = list(_tracecmd)

    if confidence is not None and confidence is not -1:
        trace_argv[-1] += " "+_traceopt_confidence+" "+str(confidence)
    if dport is not None and dport is not -1:
        trace_argv[-1] += " "+_traceopt_dport+" "+str(dport)
    if firsthop is not None and firsthop is not -1:
        trace_argv[-1] += " "+_traceopt_firsthop+" "+str(firsthop)
    if gaplimit is not None and gaplimit is not -1:
        trace_argv[-1] += " "+_traceopt_gaplimit+" "+str(gaplimit)
    if gapaction is not None and gapaction is not -1:
        trace_argv[-1] += " "+_traceopt_gapaction+" "+str(gapaction)
    if maxttl is not None and maxttl is not -1:
        trace_argv[-1] += " "+_traceopt_maxttl+" "+str(maxttl)
    if M:
        trace_argv[-1] += " "+_traceopt_M
    if loops is not None and loops is not -1:
        trace_argv[-1] += " "+_traceopt_loops+" "+str(loops)
    if loopaction is not None and loopaction is not -1:
        trace_argv[-1] += " "+_traceopt_loopaction+" "+str(loopaction)
    if payload is not None and payload is not "":
        trace_argv[-1] += " "+_traceopt_payload+" "+str(payload)
    if method is not None and method is not "":
        trace_argv[-1] += " "+_traceopt_method+" "+str(method)
    if attempts is not None and attempts is not -1:
        trace_argv[-1] += " "+_traceopt_attempts+" "+str(attempts)
    if Q:
        trace_argv[-1] += " "+_traceopt_Q
    if sport is not None and sport is not -1:
        trace_argv[-1] += " "+_traceopt_sport+" "+str(sport)
    if srcaddr:
        trace_argv[-1] += " "+_traceopt_srcaddr+" "+str(sipaddr)
    if tos is not None and tos is not -1:
        trace_argv[-1] += " "+_traceopt_tos+" "+str(tos)
    if T:
        trace_argv[-1] += " "+_traceopt_T
    if wait is not None and wait is not -1:
        trace_argv[-1] += " "+_traceopt_wait+" "+str(wait)
    if waitprobe is not None and waitprobe is not -1:
        trace_argv[-1] += " "+_traceopt_waitprobe+" "+str(waitprobe)
    #if gssentry is not None and gssentry is not "":
    #    trace_argv[-1] += " "+_traceopt_gssentry+" "+str(gssentry)
    if lssname is not None and lssname is not "":
        trace_argv[-1] += " "+_traceopt_lssname+" "+str(lssname)

    trace_argv += [_scamper_dip, str(dipaddr)]

    print("running " + " ".join(trace_argv))
    return subprocess.Popen(trace_argv, stdout=subprocess.PIPE)


def _tracelb_process(sipaddr, dipaddr, confidence, dport, firsthop, gaplimit,  method, attempts, maxprobec, sport, tos, waittimeout, waitprobe):
    tracelb_argv = list(_tracelbcmd)

    if confidence is not None and confidence is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_confidence+" "+str(confidence)
    if dport is not None and dport is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_dport+" "+str(dport)
    if firsthop is not None and firsthop is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_firsthop+" "+str(firsthop)
    if gaplimit is not None and gaplimit is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_gaplimit+" "+str(gaplimit)
    if method is not None and method is not "":
        tracelb_argv[-1] += " "+_tracelbopt_method+" "+str(method)
    if attempts is not None and attempts is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_attempts+" "+str(attempts)
    if maxprobec is not None and maxprobec is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_maxprobec+" "+str(maxprobec)
    if sport is not None and sport is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_sport+" "+str(sport)
    if tos is not None and tos is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_tos+" "+str(tos)
    if waittimeout is not None and waittimeout is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_waittimeout+" "+str(waittimeout)
    if waitprobe is not None and waitprobe is not -1:
        tracelb_argv[-1] += " "+_tracelbopt_waitprobe+" "+str(waitprobe)

    tracelb_argv += [_scamper_dip, str(dipaddr)]

    print("running " + " ".join(tracelb_argv))
    return subprocess.Popen(tracelb_argv, stdout=subprocess.PIPE)

###############################################################################
###############################  CAPABILITIES  ################################
###############################################################################

def tracebox4_standard_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracebox-standard-ip4", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")

    cap.add_result_column("scamper.tracebox.hop.ip4")
    cap.add_result_column("scamper.tracebox.hop.modifications")
    return cap

def tracebox4_specific_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracebox-specific-ip4", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")

    #cap.add_parameter("scamper.tracebox.udp","0,1")#,"0")
    cap.add_parameter("scamper.tracebox.dport","0 ... 65535")#,"80")
    cap.add_parameter("scamper.tracebox.probe","*")#,"")

    cap.add_result_column("scamper.tracebox.hop.ip4")
    cap.add_result_column("scamper.tracebox.hop.modifications")
    return cap

def tracebox4_specific_quotesize_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracebox-specific-quotesize-ip4", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")

    #cap.add_parameter("scamper.tracebox.udp","0,1")#,"0")
    cap.add_parameter("scamper.tracebox.dport","0 ... 65535")#,"80")
    cap.add_parameter("scamper.tracebox.probe","*")#,"")

    cap.add_result_column("scamper.tracebox.hop.ip4")
    cap.add_result_column("scamper.tracebox.hop.modifications")
    cap.add_result_column("scamper.tracebox.hop.icmp.payload.len")
    return cap


def tracebox6_standard_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracebox-standard-ip6", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")

    cap.add_result_column("scamper.tracebox.hop.ip6")
    cap.add_result_column("scamper.tracebox.hop.modifications")
    return cap

def tracebox6_specific_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracebox-specific-ip6", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")

    #cap.add_parameter("scamper.tracebox.udp","0,1")#,"0")
    cap.add_parameter("scamper.tracebox.dport","0 ... 65535")#,"80")
    cap.add_parameter("scamper.tracebox.probe","*")#,"")

    cap.add_result_column("scamper.tracebox.hop.ip6")
    cap.add_result_column("scamper.tracebox.hop.modifications")
    return cap

def tracebox6_specific_quotesize_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracebox-specific-quotesize-ip6", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")

    #cap.add_parameter("scamper.tracebox.udp","0,1")#,"0")
    cap.add_parameter("scamper.tracebox.dport","0 ... 65535")#,"80")
    cap.add_parameter("scamper.tracebox.probe","*")#,"")

    cap.add_result_column("scamper.tracebox.hop.ip6")
    cap.add_result_column("scamper.tracebox.hop.modifications")
    cap.add_result_column("scamper.tracebox.hop.icmp.payload.len")
    return cap

def ping4_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-ping-average-ip4", when = "now ... future / 1s")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")

    #cap.add_parameter("scamper.ping.payload","*")#,"")
    #cap.add_parameter("scamper.ping.icmp.checksum","*")#,"")
    cap.add_parameter("scamper.ping.dport","0 ... 65535")#,"80")
    cap.add_parameter("scamper.ping.sport","0 ... 65535")#,_random_sport())
    cap.add_parameter("scamper.ping.ttl","0 ... 255")#,64)
    #cap.add_parameter("scamper.ping.pattern","*")#,"")
    cap.add_parameter("scamper.ping.method","icmp-echo,icmp-time,tcp-ack,tcp-ack-sport,udp,udp-dport")#,"icmp-echo")
    cap.add_parameter("scamper.ping.rr","0 ... 1")#,0)
    cap.add_parameter("scamper.ping.size","84 ... 140")#,84)
    cap.add_parameter("scamper.ping.tos","0 ... 255")#,0)

    cap.add_result_column("delay.twoway.icmp.us.min")
    cap.add_result_column("delay.twoway.icmp.us.mean")
    cap.add_result_column("delay.twoway.icmp.us.max")
    cap.add_result_column("delay.twoway.icmp.count")
    return cap

def ping4_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-ping-detail-ip4", when = "now ... future / 1s")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")

    #cap.add_parameter("scamper.ping.payload","*")#,"")
    #cap.add_parameter("scamper.ping.icmp.checksum","*")#,"")
    cap.add_parameter("scamper.ping.dport","0 ... 65535")#"80")
    cap.add_parameter("scamper.ping.sport","0 ... 65535")#,_random_sport())
    cap.add_parameter("scamper.ping.ttl","0 ... 255")#,64)
    #cap.add_parameter("scamper.ping.pattern","*")#,"")
    cap.add_parameter("scamper.ping.method","icmp-echo,icmp-time,tcp-ack,tcp-ack-sport,udp,udp-dport")#,"icmp-echo")
    cap.add_parameter("scamper.ping.rr","0 ... 1")#,0)
    cap.add_parameter("scamper.ping.size","84 ... 140")#,84)
    cap.add_parameter("scamper.ping.tos","0 ... 255")#,0)

    cap.add_result_column("time")
    cap.add_result_column("delay.twoway.icmp.us")
    return cap

def ping6_aggregate_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-ping-average-ip6", when = "now ... future / 1s")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")

    #cap.add_parameter("scamper.ping.payload","*")#,"")
    #cap.add_parameter("scamper.ping.icmp.checksum","*")#,"")
    cap.add_parameter("scamper.ping.dport","0 ... 65535")#,"80")
    cap.add_parameter("scamper.ping.sport","0 ... 65535")#,_random_sport())
    cap.add_parameter("scamper.ping.ttl","0 ... 255")#,64)
    #cap.add_parameter("scamper.ping.pattern","*")#,"")
    cap.add_parameter("scamper.ping.method","icmp-echo,icmp-time,tcp-ack,tcp-ack-sport,udp,udp-dport")#,"icmp-echo")
    cap.add_parameter("scamper.ping.rr","0 ... 1")#,0)
    cap.add_parameter("scamper.ping.size","56 ... 140")#,56)
    cap.add_parameter("scamper.ping.tos","0 ... 255")#,0)

    cap.add_result_column("delay.twoway.icmp.us.min")
    cap.add_result_column("delay.twoway.icmp.us.mean")
    cap.add_result_column("delay.twoway.icmp.us.max")
    cap.add_result_column("delay.twoway.icmp.count")
    return cap

def ping6_singleton_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-ping-detail-ip6", when = "now ... future / 1s")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")

    #cap.add_parameter("scamper.ping.payload","*")#,"")
    #cap.add_parameter("scamper.ping.icmp.checksum","*")#,"")
    cap.add_parameter("scamper.ping.dport","0 ... 65535")#,"80")
    cap.add_parameter("scamper.ping.sport","0 ... 65535")#,_random_sport())
    cap.add_parameter("scamper.ping.ttl","0 ... 255")#,64)
    #cap.add_parameter("scamper.ping.pattern","*")#,"")
    cap.add_parameter("scamper.ping.method","icmp-echo,icmp-time,tcp-ack,tcp-ack-sport,udp,udp-dport")#,"icmp-echo")
    cap.add_parameter("scamper.ping.rr","0 ... 1")#,0)
    cap.add_parameter("scamper.ping.size","56 ... 140")#,56)
    cap.add_parameter("scamper.ping.tos","0 ... 255")#,0)

    cap.add_result_column("time")
    cap.add_result_column("delay.twoway.icmp.us")
    return cap

def trace4_standard_capability(ipaddr):
    """
          natural to float: scamper.trace.confidence, scamper.trace.dport,
                            scamper.trace.loopaction, scamper.trace.sport,
                            scamper.trace.waitprobe
    """
    cap = mplane.model.Capability(label="scamper-trace-standard-ip4", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")

    cap.add_parameter("scamper.trace.confidence","95 ... 99")#, 95)
    cap.add_parameter("scamper.trace.dport","0 ... 65535")#, 33435)
    cap.add_parameter("scamper.trace.firsthop","0 ... 255")#, 1)
    cap.add_parameter("scamper.trace.gaplimit","0 ... 255")#, 5)
    cap.add_parameter("scamper.trace.gapaction","1 ... 2")#, 1)
    cap.add_parameter("scamper.trace.maxttl","0 ... 255")#, 255)
    cap.add_parameter("scamper.trace.M","0 ... 1")#,0)
    cap.add_parameter("scamper.trace.loops","0 ... 255")#,1)
    cap.add_parameter("scamper.trace.loopaction","0 ... 1")#,0)
    #cap.add_parameter("scamper.trace.payload","*")#,"")
    cap.add_parameter("scamper.trace.method","UDP-paris,UDP,ICMP,ICMP-paris,TCP,TCP-ACK")#, "UDP-paris")
    cap.add_parameter("scamper.trace.attempts","0 ... 255")#,2)
    cap.add_parameter("scamper.trace.Q","0 ... 1")#,0)
    cap.add_parameter("scamper.trace.sport","0 ... 65535")#,_random_sport())
    #cap.add_parameter("scamper.trace.srcaddr","*")#,ipaddr)
    cap.add_parameter("scamper.trace.tos","0 ... 255")#,0)
    cap.add_parameter("scamper.trace.T","0 ... 1")#,0)
    cap.add_parameter("scamper.trace.wait","0 ... 255")#,5)
    cap.add_parameter("scamper.trace.waitprobe","0 ... 2550000")#,0)
    #cap.add_parameter("scamper.trace.gssentry","*")
    #cap.add_parameter("scamper.trace.lssname","*")

    cap.add_result_column("scamper.trace.hop.ip4")
    cap.add_result_column("rtt.ms")
    cap.add_result_column("rtt.us")
    return cap

def trace6_standard_capability(ipaddr):
    """
          natural to float: scamper.trace.confidence, scamper.trace.dport,
                            scamper.trace.loopaction, scamper.trace.sport,
                            scamper.trace.waitprobe
    """
    cap = mplane.model.Capability(label="scamper-trace-standard-ip6", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")

    cap.add_parameter("scamper.trace.confidence","95,99")#,95)
    cap.add_parameter("scamper.trace.dport","0 ... 65535")#, 33435)
    cap.add_parameter("scamper.trace.firsthop","0 ... 255")#, 1)
    cap.add_parameter("scamper.trace.gaplimit","0 ... 255")#, 5)
    cap.add_parameter("scamper.trace.gapaction","1 ... 2")#, 1)
    cap.add_parameter("scamper.trace.maxttl","0 ... 255")#, 255)
    cap.add_parameter("scamper.trace.M","0 ... 1")#,0)
    cap.add_parameter("scamper.trace.loops","0 ... 255")#,1)
    cap.add_parameter("scamper.trace.loopaction","0 ... 1")#,0)
    #cap.add_parameter("scamper.trace.payload","*")#,"")
    cap.add_parameter("scamper.trace.method","UDP-paris,UDP,ICMP,ICMP-paris,TCP,TCP-ACK")#, "UDP-paris")
    cap.add_parameter("scamper.trace.attempts","0 ... 255")#,2)
    cap.add_parameter("scamper.trace.Q","0 ... 1")#,0)
    cap.add_parameter("scamper.trace.sport","0 ... 65535")#,_random_sport())
    #cap.add_parameter("scamper.trace.srcaddr","*")#,ipaddr)
    cap.add_parameter("scamper.trace.tos","0 ... 255")#,0)
    cap.add_parameter("scamper.trace.T","0 ... 1")#,0)
    cap.add_parameter("scamper.trace.wait","0 ... 255")#,5)
    cap.add_parameter("scamper.trace.waitprobe","0 ... 2550000")#,0)
    #cap.add_parameter("scamper.trace.gssentry","*")
    #cap.add_parameter("scamper.trace.lssname","*")

    cap.add_result_column("scamper.trace.hop.ip6")
    cap.add_result_column("rtt.ms")
    cap.add_result_column("rtt.us")
    return cap

def tracelb4_standard_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracelb-standard-ip4", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip4",ipaddr)
    cap.add_parameter("destination.ip4")

    cap.add_parameter("scamper.tracelb.confidence","95 ... 99")#,95)
    cap.add_parameter("scamper.tracelb.dport","0 ... 65535")#, 33435)
    cap.add_parameter("scamper.tracelb.firsthop","0 ... 255")#, 1)
    cap.add_parameter("scamper.tracelb.gaplimit","0 ... 255")#, 5)
    cap.add_parameter("scamper.tracelb.method","udp-dport,icmp-echo,udp-sport,tcp-sport,tcp-ack-sport,udp-dport")#"udp-dport"
    cap.add_parameter("scamper.tracelb.attempts","0 ... 255")#,2)
    cap.add_parameter("scamper.tracelb.maxprobec","1 ... 10000")#,3000)
    cap.add_parameter("scamper.tracelb.sport","0 ... 65535")#,_random_sport())
    cap.add_parameter("scamper.tracelb.tos","0 ... 255")#,0)
    cap.add_parameter("scamper.tracelb.waittimeout","0 ... 255")#,5)
    cap.add_parameter("scamper.tracelb.waitprobe","0 ... 2550000")#,0)

    cap.add_result_column("scamper.tracelb.result")
    return cap

def tracelb6_standard_capability(ipaddr):
    cap = mplane.model.Capability(label="scamper-tracelb-standard-ip6", when = "now ... future")
    cap.add_metadata("System_type", "Scamper")
    cap.add_metadata("System_ID", "Scamper-Proxy")
    cap.add_metadata("System_version", "0.1")

    cap.add_parameter("source.ip6",ipaddr)
    cap.add_parameter("destination.ip6")

    cap.add_parameter("scamper.tracelb.confidence","95 ... 99")#,95)
    cap.add_parameter("scamper.tracelb.dport","0 ... 65535")#, 33435)
    cap.add_parameter("scamper.tracelb.firsthop","0 ... 255")#, 1)
    cap.add_parameter("scamper.tracelb.gaplimit","0 ... 255")#, 5)
    cap.add_parameter("scamper.tracelb.method","udp-dport,icmp-echo,udp-sport,tcp-sport,tcp-ack-sport,udp-dport")#"udp-dport"
    cap.add_parameter("scamper.tracelb.attempts","0 ... 255")#,2)
    cap.add_parameter("scamper.tracelb.maxprobec","1 ... 10000")#,3000)
    cap.add_parameter("scamper.tracelb.sport","0 ... 65535")#,_random_sport())
    cap.add_parameter("scamper.tracelb.tos","0 ... 255")#,0)
    cap.add_parameter("scamper.tracelb.waittimeout","0 ... 255")#,5)
    cap.add_parameter("scamper.tracelb.waitprobe","0 ... 2550000")#,0)

    cap.add_result_column("scamper.tracelb.result")
    return cap

###############################################################################
#################################  SERVICE  ###################################
###############################################################################

class ScamperService(mplane.scheduler.Service):

    #default tracebox parameter values
    _default_udp=0
    _default_dport=80
    def _default_probe(self,udp):
        return "IP/"+("UDP" if udp else "TCP")

    #label keywords
    _quote_size="quotesize"

    __available_services=["dealias","neighbourdisc","ping","tracebox","tracelb","trace","sniff"]

    def __init__(self, cap):
        # verify the capability is acceptable
        if not ((cap.has_parameter("source.ip4") or
                 cap.has_parameter("source.ip6")) and
                (cap.has_parameter("destination.ip4") or
                 cap.has_parameter("destination.ip6"))):
            raise ValueError("capability not acceptable")

        super(ScamperService, self).__init__(cap)
        self._get_ipl = 1 if self._quote_size in self.capability().get_label() else None

        #init service
        for serv in self.__available_services:
            if serv in self.capability().get_label():
                self.__service=serv
                print(serv)
                break
        self.__input_funcs   = {"dealias":self.__input_dealias,
                                "neighbourdisc":self.__input_neighbourdisc,
                                "ping":self.__input_ping,
                                "trace":self.__input_trace,
                                "tracelb":self.__input_tracelb,
                                "sniff":self.__input_sniff,
                                "tracebox":self.__input_tracebox}
        self.__parsing_funcs = {"dealias":self.__input_dealias,
                                "neighbourdisc":self.__input_neighbourdisc,
                                "ping":self.__parse_ping,
                                "trace":_parse_trace,
                                "tracelb":self.__parse_tracelb,
                                "sniff":self.__input_sniff,
                                "tracebox":self.__parse_tracebox}
        self.__output_funcs  = {"dealias":self.__input_dealias,
                                "neighbourdisc":self.__input_neighbourdisc,
                                "ping":self.__output_ping,
                                "trace":self.__output_trace,
                                "tracelb":self.__output_tracelb,
                                "sniff":self.__input_sniff,
                                "tracebox":self.__output_tracebox}
        self.__capabilities_funcs = [tracebox4_standard_capability,
                                     tracebox4_specific_capability,
                                     tracebox4_specific_quotesize_capability,
                                     ping4_aggregate_capability,
                                     ping4_singleton_capability,
                                     trace4_standard_capability,
                                     tracelb4_standard_capability,
                                     ping6_aggregate_capability,
                                     ping6_singleton_capability,
                                     tracebox6_standard_capability,
                                     tracebox6_specific_capability,
                                     tracebox6_specific_quotesize_capability,
                                     trace6_standard_capability,
                                     tracelb6_standard_capability]

    def capabilities(self):
        """
        returns a list of mplane.model.Capability objects
        representing the capabilities of this component
        """
        return [f() for f in self.__capabilities_funcs]

    ########################### INPUT #########################
    def __input_dealias(self):
        return

    def __input_neighbourdisc(self):
        return

    def __input_ping(self,spec):
        period = int(spec.when().period().total_seconds())
        duration = int(spec.when().duration().total_seconds())
        if duration is not None and duration > 0:
            count = int(duration / period)
        else:
            count = None
        payload = None#spec.get_parameter_value("scamper.ping.payload")
        chksum  = None#spec.get_parameter_value("scamper.ping.icmp.checksum")
        dport   = spec.get_parameter_value("scamper.ping.dport")
        sport   = spec.get_parameter_value("scamper.ping.sport")
        ttl     = spec.get_parameter_value("scamper.ping.ttl")
        pattern = None#spec.get_parameter_value("scamper.ping.pattern")
        method  = spec.get_parameter_value("scamper.ping.method")
        rr      = spec.get_parameter_value("scamper.ping.rr")
        size    = spec.get_parameter_value("scamper.ping.size")
        tos     = spec.get_parameter_value("scamper.ping.tos")
        if spec.has_parameter("scamper.ping.rcount"):
            rcount  = spec.get_parameter_value("scamper.ping.rcount")
        else:
            rcount  = -1

        if spec.has_parameter("destination.ip4"):
            sipaddr = spec.get_parameter_value("source.ip4")
            dipaddr = spec.get_parameter_value("destination.ip4")
            ping_process = _ping_process(sipaddr, dipaddr, period, count, payload, chksum, dport, sport, ttl, pattern, method, rr, size, tos, rcount)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            ping_process = _ping_process(sipaddr, dipaddr, period, count, payload, chksum, dport, sport, ttl, pattern, method, rr, size, tos, rcount)
        else:
            raise ValueError("Missing destination")

        return ping_process

    def __input_trace(self,spec):
        # retreive parameters. if no value, sets tracebox default value
        confidence = spec.get_parameter_value("scamper.trace.confidence")
        dport      = spec.get_parameter_value("scamper.trace.dport")
        firsthop   = spec.get_parameter_value("scamper.trace.firsthop")
        gaplimit   = spec.get_parameter_value("scamper.trace.gaplimit")
        gapaction  = spec.get_parameter_value("scamper.trace.gapaction")
        maxttl     = spec.get_parameter_value("scamper.trace.maxttl")
        M          = spec.get_parameter_value("scamper.trace.M")
        loops      = spec.get_parameter_value("scamper.trace.loops")
        loopaction = spec.get_parameter_value("scamper.trace.loopaction")
        payload    = None#spec.get_parameter_value("scamper.trace.payload")
        method     = spec.get_parameter_value("scamper.trace.method")
        attempts   = spec.get_parameter_value("scamper.trace.attempts")
        Q          = spec.get_parameter_value("scamper.trace.Q")
        sport      = spec.get_parameter_value("scamper.trace.sport")
        srcaddr    = sipaddr#spec.get_parameter_value("scamper.trace.srcaddr")
        tos        = spec.get_parameter_value("scamper.trace.tos")
        T          = spec.get_parameter_value("scamper.trace.T")
        wait       = spec.get_parameter_value("scamper.trace.wait")
        waitprobe  = spec.get_parameter_value("scamper.trace.waitprobe")
        gssentry   = None#spec.get_parameter_value("scamper.trace.gssentry")
        lssname    = None#spec.get_parameter_value("scamper.trace.lssname")

        #launch probe
        if spec.has_parameter("destination.ip4"):
            sipaddr = spec.get_parameter_value("source.ip4")
            dipaddr = spec.get_parameter_value("destination.ip4")
            trace_process = _trace_process(sipaddr, dipaddr, confidence, dport, firsthop, gaplimit, gapaction, maxttl, M, loops, loopaction, payload, method, attempts, Q, sport, srcaddr, tos, T, wait, waitprobe, lssname)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            trace_process = _trace_process(sipaddr, dipaddr,confidence, dport, firsthop, gaplimit, gapaction, maxttl, M, loops, loopaction, payload, method, attempts, Q, sport, srcaddr, tos, T, wait, waitprobe, lssname)
        else:
            raise ValueError("Missing destination")

        return trace_process

    def __input_tracelb(self,spec):
        confidence  = spec.get_parameter_value("scamper.tracelb.confidence")
        dport       = spec.get_parameter_value("scamper.tracelb.dport")
        firsthop    = spec.get_parameter_value("scamper.tracelb.firsthop")
        gaplimit    = spec.get_parameter_value("scamper.tracelb.gaplimit")
        method      = spec.get_parameter_value("scamper.tracelb.method")
        attempts    = spec.get_parameter_value("scamper.tracelb.attempts")
        maxprobec   = spec.get_parameter_value("scamper.tracelb.maxprobec")
        sport       = spec.get_parameter_value("scamper.tracelb.sport")
        tos         = spec.get_parameter_value("scamper.tracelb.tos")
        waittimeout = spec.get_parameter_value("scamper.tracelb.waittimeout")
        waitprobe   = spec.get_parameter_value("scamper.tracelb.waitprobe")

        #launch probe
        if spec.has_parameter("destination.ip4"):
            sipaddr = spec.get_parameter_value("source.ip4")
            dipaddr = spec.get_parameter_value("destination.ip4")
            tracelb_process = _tracelb_process(sipaddr, dipaddr, confidence, dport, firsthop, gaplimit,  method, attempts, maxprobec, sport, tos, waittimeout, waitprobe)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            tracelb_process = _tracelb_process(sipaddr, dipaddr,confidence, dport, firsthop, gaplimit,  method, attempts, maxprobec, sport, tos, waittimeout, waitprobe)
        else:
            raise ValueError("Missing destination")

        return tracelb_process


    def __input_sniff(self):
        return

    def __input_tracebox(self,spec):
        # retreive parameters. if no value, sets tracebox default value
        if spec.has_parameter("scamper.tracebox.udp"):
            udp=spec.get_parameter_value("scamper.tracebox.udp")
            if udp is None:
                spec.set_parameter_value("scamper.tracebox.udp",self._default_udp)
        else:
            udp=None

        if spec.has_parameter("scamper.tracebox.dport"):
            dport=spec.get_parameter_value("scamper.tracebox.dport")
            if dport is None:
                spec.set_parameter_value("scamper.tracebox.dport",self._default_dport)
        else:
            dport=None

        if spec.has_parameter("scamper.tracebox.probe"):
            probe=spec.get_parameter_value("scamper.tracebox.probe")
            if probe is None:
                spec.set_parameter_value("scamper.tracebox.probe",self._default_probe(udp))
        else:
            probe=None

        #launch probe
        if spec.has_parameter("destination.ip4"):
            sipaddr = spec.get_parameter_value("source.ip4")
            dipaddr = spec.get_parameter_value("destination.ip4")
            tracebox_process = _tracebox4_process(sipaddr, dipaddr, udp=udp, dport=dport, probe=probe, get_icmp_payload_len=self._get_ipl)
        elif spec.has_parameter("destination.ip6"):
            sipaddr = spec.get_parameter_value("source.ip6")
            dipaddr = spec.get_parameter_value("destination.ip6")
            tracebox_process = _tracebox6_process(sipaddr, dipaddr, udp=udp, dport=dport, probe=probe, get_icmp_payload_len=self._get_ipl)
        else:
            raise ValueError("Missing destination")

        return tracebox_process

    ########################### PARSING #########################
    def __parse_tracebox(self,tb_output):
        """
        returns list of tuple (intermediate.addr, intermediate.modifs)
        """
        tuples=[]
        if (len(tb_output)<3):
            return []

        min_words = 3 if self._get_ipl else 2

        for i, line in enumerate(tb_output[2:]):
            pline=line.split()
            # Skip ICMPs/RSTs
            if ((len(pline) == 1 and pline[-1][-1] != ':') or
                (len(pline) == 2 and pline[-1][-1] != '*'
                                 and ':' not in pline[-1])):
                continue
            elif pline[1] == "*":
                tuples.append(TraceboxValue(pline[1], "", ""))
            elif len(pline)<=min_words:
                if line == tb_output[-1]:
                    tuples.append(TraceboxValue(pline[1], pline[2],""))
                else:
                    tuples.append(TraceboxValue(pline[1], "", _detail_ipl(pline[2]) if self._get_ipl else ""))
            else:
                tuples.append(TraceboxValue(pline[1]," ".join(pline[min_words:]), _detail_ipl(pline[2]) if self._get_ipl else ""))
        return tuples

    def __parse_ping(self,ping_process):
        pings = []
        for line in ping_process:
            oneping = _parse_ping_line(line)
            if oneping is not None:
                print("ping "+repr(oneping))
                pings.append(oneping)
        return pings

    def __parse_tracelb(self,tracelb_process):
        tuples = []
        for line in tracelb_process[1:]:
            tuples.append(line.rstrip('\n'))
        return tuples

    ########################### OUTPUT #########################
    def __output_tracebox(self,res,parsed_output):
        for i, onehop in enumerate(parsed_output):
            print("tracebox "+repr(onehop))
            if res.has_parameter("destination.ip4"):
                res.set_result_value("scamper.tracebox.hop.ip4", onehop.addr,i)
            else:
                res.set_result_value("scamper.tracebox.hop.ip6", onehop.addr,i)
            res.set_result_value("scamper.tracebox.hop.modifications", onehop.modifs,i)
            if self._get_ipl:
                res.set_result_value("scamper.tracebox.hop.icmp.payload.len", onehop.payload_len, i)
        return res

    def __output_trace(self,res,parsed_output):
        for i, onehop in enumerate(parsed_output):
            print("trace "+repr(onehop))
            if res.has_parameter("destination.ip4"):
                res.set_result_value("scamper.trace.hop.ip4", onehop.addr,i)
            else:
                res.set_result_value("scamper.trace.hop.ip6", onehop.addr,i)


            if onehop.rtt is not "NaN":
                rtt_ms = int(float(onehop.rtt))
                rtt_us = float(onehop.rtt) * 1000
                res.set_result_value("rtt.ms", rtt_ms,i)
                res.set_result_value("rtt.us", rtt_us,i)
        return res

    def __output_ping(self,res,pings):
        if res.has_result_column("delay.twoway.icmp.us"):
            # raw numbers
            for i, oneping in enumerate(pings):
                res.set_result_value("delay.twoway.icmp.us", oneping.usec, i)
            if res.has_result_column("time"):
                for i, oneping in enumerate(pings):
                    res.set_result_value("time", oneping.time, i)
        else:
            # aggregates. single row.
            if res.has_result_column("delay.twoway.icmp.us.min"):
                res.set_result_value("delay.twoway.icmp.us.min", pings_min_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.mean"):
                res.set_result_value("delay.twoway.icmp.us.mean", pings_mean_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.median"):
                res.set_result_value("delay.twoway.icmp.us.median", pings_median_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.max"):
                res.set_result_value("delay.twoway.icmp.us.max", pings_max_delay(pings))
            if res.has_result_column("delay.twoway.icmp.us.count"):
                res.set_result_value("delay.twoway.icmp.us.count", len(pings))

        return res

    def __output_tracelb(self,res,lines):
        for i, line in enumerate(lines):
            print(line)
            res.set_result_value("scamper.tracelb.result",line, i)

        return res

    ########################### RUN #########################
    def run(self, spec, check_interrupt):

        #save probe start time
        start_time=datetime.utcnow()

        #process
        process=self.__input_funcs[self.__service](spec)

        #save probe end time
        end_time=datetime.utcnow()

        # read and parse output from tracebox
        output = []
        for line in process.stdout:
            output.append(line.decode("utf-8"))

        #parse output
        parsed_output = self.__parsing_funcs[self.__service](output)

        # shut down and reap
        try:
            process.kill()
        except OSError:
            pass
        process.wait()

        # derive a result from the specification
        res = mplane.model.Result(specification=spec)

        # put actual start and end time into result
        res.set_when(mplane.model.When(a = start_time, b = end_time))

        # output
        res = self.__output_funcs[self.__service](res,parsed_output)

        return res


def services(ip4addr = None, ip6addr = None):
    services = []
    if ip4addr is not None:
        services.append(ScamperService(tracebox4_standard_capability(ip4addr)))
        services.append(ScamperService(tracebox4_specific_capability(ip4addr)))
        services.append(ScamperService(tracebox4_specific_quotesize_capability(ip4addr)))
        services.append(ScamperService(ping4_aggregate_capability(ip4addr)))
        services.append(ScamperService(ping4_singleton_capability(ip4addr)))
        services.append(ScamperService(trace4_standard_capability(ip4addr)))
        services.append(ScamperService(tracelb4_standard_capability(ip4addr)))
    if ip6addr is not None:
        services.append(ScamperService(ping6_aggregate_capability(ip6addr)))
        services.append(ScamperService(ping6_singleton_capability(ip6addr)))
        services.append(ScamperService(tracebox6_standard_capability(ip6addr)))
        services.append(ScamperService(tracebox6_specific_capability(ip6addr)))
        services.append(ScamperService(tracebox6_specific_quotesize_capability(ip6addr)))
        services.append(ScamperService(trace6_standard_capability(ip6addr)))
        services.append(ScamperService(tracelb6_standard_capability(ip6addr)))
    return services

