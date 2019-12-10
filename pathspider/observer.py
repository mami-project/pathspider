import collections
import logging
import base64
import queue
import math

from pathspider.base import SHUTDOWN_SENTINEL


def _flow4_ids(ip):
    # FIXME keep map of fragment IDs to keys (#144)

    icmp_with_payload = {3, 4, 5, 11, 12}
    quotation_fid = False
    if ip.proto == 1 and ip.icmp.type in icmp_with_payload:
        if ip.icmp.payload is not None and len(ip.icmp.payload.data) >= 20:
            ip = ip.icmp.payload
            quotation_fid = True

    protos_with_ports = {6, 17, 132, 136}
    if ip.proto in protos_with_ports:
        # key includes ports
        fid = ip.src_prefix.addr + ip.dst_prefix.addr + ip.data[
            9:10] + ip.payload[0:4]
        rid = ip.dst_prefix.addr + ip.src_prefix.addr + ip.data[
            9:10] + ip.payload[2:4] + ip.payload[0:2]
    else:
        # no ports, just 3-tuple
        fid = ip.src_prefix.addr + ip.dst_prefix.addr + ip.data[9:10]
        rid = ip.dst_prefix.addr + ip.src_prefix.addr + ip.data[9:10]

    if quotation_fid:
        # If the fid is based on an ICMP quotation, need to be reversed
        return (base64.b64encode(rid), base64.b64encode(fid))
    else:
        return (base64.b64encode(fid), base64.b64encode(rid))


def _flow6_ids(ip6):
    icmp_with_payload = {1, 2, 3, 4}
    quotation_fid = False

    if ip6.proto == 58 and ip6.icmp6.type in icmp_with_payload:
        if ip6.icmp6.payload is not None and len(ip6.icmp6.payload.data) >= 40:
            ip6 = ip6.icmp6.payload
            quotation_fid = True

    protos_with_ports = {6, 17, 132, 136}
    hdr_opts = {0, 60}
    if ip6.proto in protos_with_ports:
        # key gets the protocol from the IPv6 HBH or Destination Options header
        if ip6.next_hdr in hdr_opts:
            fid = ip6.src_prefix.addr + ip6.dst_prefix.addr + ip6.data[
                40:41] + ip6.payload[0:4]
            rid = ip6.dst_prefix.addr + ip6.src_prefix.addr + ip6.data[
                40:41] + ip6.payload[2:4] + ip6.payload[0:2]
        # key includes ports
        else:
            fid = ip6.src_prefix.addr + ip6.dst_prefix.addr + ip6.data[
                6:7] + ip6.payload[0:4]
            rid = ip6.dst_prefix.addr + ip6.src_prefix.addr + ip6.data[
                6:7] + ip6.payload[2:4] + ip6.payload[0:2]
    else:
        # no ports, just 3-tuple
        fid = ip6.src_prefix.addr + ip6.dst_prefix.addr + ip6.data[6:7]
        rid = ip6.dst_prefix.addr + ip6.src_prefix.addr + ip6.data[6:7]

    if quotation_fid:
        # If the fid is based on an ICMP quotation, need to be reversed
        return (base64.b64encode(rid), base64.b64encode(fid))
    else:
        return (base64.b64encode(fid), base64.b64encode(rid))


PacketClockTimer = collections.namedtuple("PacketClockTimer", ("time", "fn"))


class Observer:
    """
    Wraps a packet source identified by a libtrace URI,
    parses packets to divide them into flows, passing these
    packets and flows onto a function chain to allow
    data to be associated with each flow.
    """

    def __init__(self, lturi, chains=None, idle_timeout=30, expiry_timeout=5,
                 aggregate=False):
        """
        Create an Observer.

        :param chains: Array of Observer chain classes
        :see also: :ref:`Observer Documentation <observer>`
        """

        # Only import this when needed
        import plt as libtrace

        # Control
        self._irq = None
        self._irq_fired = False
        self._aggregate = aggregate

        # Libtrace initialization
        self._trace = libtrace.trace(lturi)  # pylint: disable=no-member
        self._trace.start()
        self._pkt = libtrace.packet()  # pylint: disable=no-member

        # Chains of functions to evaluate
        chains = chains if chains is not None else []
        self._chains = [chain() for chain in chains]

        # Packet timer and bintables
        self._ptq = 0  # current packet timer, quantized
        self._idle_bins = {}  # map bin number to set of fids
        self._expiry_bins = {}  # map bin number to set of fids
        self._idle_timeout = idle_timeout
        self._expiry_timeout = expiry_timeout
        self._bin_quantum = 1

        #self._tq = []                  # packet timer queue (heap)

        # Flow tables
        self._active = {}
        self._expiring = {}
        self._ignored = set()

        # Emitter queue
        self._emitted = collections.deque()

        # Statistics and logging
        self._logger = logging.getLogger("observer")
        self._ct_pkt = 0
        self._ct_nonip = 0
        self._ct_shortkey = 0
        self._ct_ignored = 0
        self._ct_flow = 0

    def _interrupted(self):
        if not self._irq_fired and self._irq is not None:
            try:
                self._irq.get_nowait()
                self._irq_fired = True
            except queue.Empty:
                pass

        return self._irq_fired

    def _get_chains(self, name):
        return [
            c.__getattribute__(name) for c in self._chains if hasattr(c, name)
        ]

    def _next_packet(self):
        # Import only when needed
        import plt as libtrace

        # see if someone told us to stop
        if self._interrupted():
            return False

        # see if we're done iterating
        if not self._trace.read_packet(self._pkt):
            return False

        # count the packet
        self._ct_pkt += 1

        # advance the packet clock
        self._tick(self._pkt.seconds)

        # get a flow ID and associated flow record for the packet
        (fid, rec, rev) = self._get_flow()

        # don't dispatch if we don't have a record
        # (this happens for non-IP packets and flows
        #  we know we want to ignore)
        if not rec:
            return True

        keep_flow = True

        # run IP header chains
        if self._pkt.ip:
            for fn in self._get_chains("ip4"):
                keep_flow = keep_flow and fn(rec, self._pkt.ip, rev=rev)
            if self._pkt.icmp:
                for fn in self._get_chains("icmp4"):
                    q = self._pkt.icmp.payload # pylint: disable=no-member
                    keep_flow = keep_flow and fn(rec, self._pkt.ip, q, rev=rev)

        elif self._pkt.ip6:
            for fn in self._get_chains("ip6"):
                keep_flow = keep_flow and fn(rec, self._pkt.ip6, rev=rev)
            if self._pkt.icmp6:
                for fn in self._get_chains("icmp6"):
                    q = self._pkt.icmp6.payload # pylint: disable=no-member
                    keep_flow = keep_flow and fn(
                        rec, self._pkt.ip6, q, rev=rev)

        # run transport header chains
        if self._pkt.tcp:
            for fn in self._get_chains("tcp"):
                keep_flow = keep_flow and fn(rec, self._pkt.tcp, rev=rev)
        elif self._pkt.udp:
            for fn in self._get_chains("udp"):
                keep_flow = keep_flow and fn(rec, self._pkt.udp, rev=rev)

        # complete the flow if any chain function asked us to
        if not keep_flow:
            self._flow_complete(fid)

        # we processed a packet, keep going
        return True

    # def _set_timer(self, delay, fid):
    #     # add to queue
    #     heapq.heappush(self._tq, PacketClockTimer(self._pt + delay,
    #                    self._finish_expiry_tfn(fid)))

    def _get_flow(self):
        """
        Get a flow record for the given packet.
        Create a new basic flow record
        """
        # get possible a flow IDs for the packet
        try:
            if self._pkt.ip:
                (ffid, rfid) = (4, 5) if self._aggregate else _flow4_ids(
                    self._pkt.ip)
                ip = self._pkt.ip
            elif self._pkt.ip6:
                (ffid, rfid) = (4, 5) if self._aggregate else _flow6_ids(
                    self._pkt.ip6)
                ip = self._pkt.ip6
            else:
                # we don't care about non-IP packets
                self._ct_nonip += 1
                return (None, None, False)
        except ValueError:
            self._ct_shortkey += 1
            return (None, None, False)

        # now look for forward and reverse in ignored, active,
        # and expiring tables.
        if ffid in self._ignored:
            return (None, None, False)
        elif rfid in self._ignored:
            return (None, None, False)
        elif ffid in self._active:
            (fid, rec, active) = (ffid, self._active[ffid], True)
            #self._logger.debug("found forward flow for "+str(ffid))
        elif ffid in self._expiring:
            (fid, rec, active) = (ffid, self._expiring[ffid], False)
            #self._logger.debug("found expiring forward flow for "+str(ffid))
        elif rfid in self._active:
            (fid, rec, active) = (rfid, self._active[rfid], True)
            #self._logger.debug("found reverse flow for "+str(rfid))
        elif rfid in self._expiring:
            (fid, rec, active) = (rfid, self._expiring[rfid], False)
            #self._logger.debug("found expiring reverse flow for "+str(rfid))
        else:
            # nowhere to be found. new flow.
            rec = {'pkt_first': ip.seconds, '_idle_bin': 0}
            for fn in self._get_chains("new_flow"):
                if not fn(rec, ip):
                    # self._logger.debug("ignoring "+str(ffid))
                    self._ignored.add(ffid)
                    self._ct_ignored += 1
                    return (None, None, False)

            # wasn't vetoed. add to active table.
            fid = ffid
            self._active[ffid] = rec
            active = True
            # self._logger.debug("new flow for "+str(ffid))
            self._ct_flow += 1

        # update time and idle bin and return record
        rec['pkt_last'] = ip.seconds

        # update idle bin if we're not expiring
        if active:
            new_idle_bin = math.ceil((rec['pkt_last'] + self._idle_timeout) /
                                     self._bin_quantum) * self._bin_quantum

            if new_idle_bin > rec["_idle_bin"]:

                if rec['_idle_bin'] in self._idle_bins:
                    self._idle_bins[rec['_idle_bin']] -= set((fid, ))
                if new_idle_bin in self._idle_bins:
                    self._idle_bins[new_idle_bin] |= set((fid, ))
                else:
                    self._idle_bins[new_idle_bin] = set((fid, ))

                rec['_idle_bin'] = new_idle_bin

        return (fid, rec, bool(fid == rfid))

    def _flow_complete(self, fid):
        """
        Mark a given flow ID as complete
        """
        # skip all of this unless the flow is still in the active table
        if fid not in self._active:
            return

        # remove flow ID from idle bin
        rec = self._active[fid]
        self._idle_bins[rec['_idle_bin']] -= set((fid, ))

        del rec['_idle_bin']

        # move record to expiring table
        self._expiring[fid] = rec
        del self._active[fid]

        # assign expiry bin
        expiry_bin = math.ceil((self._ptq + self._expiry_timeout) /
                               self._bin_quantum) * self._bin_quantum
        #self._logger.debug("Completing flow "+str(fid)+" at "+str(self._ptq)+" to expire "+str(expiry_bin)+" (in "+str(expiry_bin-self._ptq)+"s)")

        if expiry_bin in self._expiry_bins:
            self._expiry_bins[expiry_bin] |= set((fid, ))
        else:
            self._expiry_bins[expiry_bin] = set((fid, ))

    def _emit_flow(self, rec):
        self._emitted.append(rec)

    def _next_flow(self):
        while len(self._emitted) == 0:
            if not self._next_packet():
                return None

        return self._emitted.popleft()

    def _tick(self, pt):
        # quantize and skip if we're not advancing
        next_ptq = math.ceil(pt / self._bin_quantum) * self._bin_quantum
        if next_ptq <= self._ptq:
            return
        elif self._ptq == 0:
            # handle zero case
            self._ptq = next_ptq
            return

        # advance quantum
        for bint in range(self._ptq + self._bin_quantum,
                          next_ptq + self._bin_quantum, self._bin_quantum):
            self._logger.debug("tick: " + str(bint))

            # process idle
            if bint in self._idle_bins:
                if len(self._idle_bins[bint]) > 0:
                    for fid in self._idle_bins[bint].copy():
                        self._flow_complete(fid)
                del self._idle_bins[bint]

            # process expiry
            if bint in self._expiry_bins:
                if len(self._expiry_bins[bint]) > 0:
                    for fid in self._expiry_bins[bint].copy():
                        self._emit_flow(self._expiring[fid])
                        del self._expiring[fid]
                del self._expiry_bins[bint]

        self._ptq = next_ptq

    # def _tick(self, pt):
    #     # Advance packet clock
    #     self._pt = pt

    #     # fire all timers whose time has come
    #     while len(self._tq) > 0 and pt > min(self._tq, key=lambda x: x.time).time:
    #         try:
    #             heapq.heappop(self._tq).fn()
    #         except:
    #             type, value, tb = sys.exc_info()
    #             traceback.print_exc()
    #             pdb.post_mortem(tb)

    # def _finish_expiry_tfn(self, fid):
    #     """
    #     On expiry timer, emit the flow
    #     and delete it from the expiring queue
    #     """
    #     def tfn():
    #         if fid in self._expiring:
    #             self._emit_flow(self._expiring[fid])
    #             del self._expiring[fid]
    #             # self._logger.debug("emitted "+str(fid)+" on expiry")
    #     return tfn

    # def purge_idle(self, timeout=30):
    #     # TODO test this, it's probably pretty slow.
    #     for fid in self._active:
    #         if self._pt - self._active['fid']['last'] > timeout:
    #             self._flow_complete(fid)

    def flush(self):
        for fid in self._expiring:
            self._emit_flow(self._expiring[fid])
            # self._logger.debug("emitted "+str(fid)+" expiring during flush")
        self._expiring.clear()

        for fid in self._active:
            self._emit_flow(self._active[fid])
            # self._logger.debug("emitted "+str(fid)+" active during flush")
        self._active.clear()

        self._ignored.clear()

    def run_flow_enqueuer(self, flowqueue, irqueue=None):
        if irqueue:
            self._irq = irqueue
            self._irq_fired = None

        # Run main loop until last packet seen
        # then flush active flows and run again
        for _ in range(2):
            while True:
                f = self._next_flow()
                if f:
                    flowqueue.put(f)
                else:
                    self.flush()
                    break

        # log observer info on shutdown
        self._logger.info(("processed %u packets "
                           "(%u dropped, %u short, %u non-ip) "
                           "into %u flows (%u ignored)"), self._ct_pkt,
                          self._trace.pkt_drops(), self._ct_shortkey,
                          self._ct_nonip, self._ct_flow, self._ct_ignored)

        flowqueue.put(SHUTDOWN_SENTINEL)


class DummyObserver:  # pylint: disable=R0903
    """
    The dummy observer provides a class compatible with the API of the Observer
    class without actually performing any operations.  This is primarily used
    for PATHspider's test suite.
    """

    def run_flow_enqueuer(self, flowqueue, irqueue=None):  # pylint: disable=R0201
        """
        When running the flow enqueuer, no network operation is performed and
        the thread will block until given a shutdown signal. When the shutdown
        signal is received it will cascade the signal onto the flowqueue
        in the same way that a real Observer instance would.
        """

        irqueue.get()
        flowqueue.put(SHUTDOWN_SENTINEL)
