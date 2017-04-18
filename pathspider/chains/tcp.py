"""
.. module:: pathspider.chains.tcp
   :synopsis: A flow observer chain for basic TCP behaviour, TCP options
              parser and useful TCP related constants

This module contains the TCPChain flow analysis chain which can be used by
PATHspider's Observer for recording basic TCP [RFC793]_ behaviour details. This
module also contains a helper function that may be used by chains for the
parsing of TCP options and a number of useful TCP related constants that can be
used to interpret the results added to flow records by TCPChain.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>
.. codeauthor:: Piet De Vaere <piet@devae.re>

"""

from pathspider.chains.base import Chain

#: TCP Flag - CWR
TCP_CWR = 0x80
#: TCP Flag - ECE
TCP_ECE = 0x40
#: TCP Flag - URG
TCP_URG = 0x20
#: TCP Flag - ACK
TCP_ACK = 0x10
#: TCP Flag - PSH
TCP_PSH = 0x08
#: TCP Flag - RST
TCP_RST = 0x04
#: TCP Flag - SYN
TCP_SYN = 0x02
#: TCP Flag - FIN
TCP_FIN = 0x01

#: TCP Flags - SYN and ACK
TCP_SA = (TCP_SYN | TCP_ACK)
#: TCP Flags - SYN, ACK and ECE
TCP_SEC = (TCP_SYN | TCP_ECE | TCP_CWR)
#: TCP Flags - SYN, ACK, ECE and CWR
TCP_SAEC = (TCP_SYN | TCP_ACK | TCP_ECE | TCP_CWR)
#: TCP Flags - SYN, ACK, ECE
TCP_SAE = (TCP_SYN | TCP_ACK | TCP_ECE)

#: TCP Option - End of options list
TO_EOL = 0
#: TCP Option - No Operation
TO_NOP = 1
#: TCP Option - Maximum Segment Size
TO_MSS = 2
#: TCP Option - Window Scaling
TO_WS = 3
#: TCP Option - Selective Acknowledgement Permitted
TO_SACKOK = 4
#: TCP Option - Selective Acknowledgement
TO_SACK = 5
#: TCP Option - Timestamp
TO_TS = 8
#: TCP Option - Multipath TCP
TO_MPTCP = 30
#: TCP Option - TCP Fast Open Cookie
TO_FASTOPEN = 34
#: TCP Option - Experimental Option A
TO_EXPA = 254
#: TCP Option - Experimental Option B
TO_EXPB = 255
#: TCP Option Experiment ID - TCP Fast Open
TO_EXID_FASTOPEN = (0xF9, 0x89)

def tcp_options(tcp):
    """
    Parses and extracts TCP options from a python-libtrace TCP object.

    .. warning:: This is a pure Python implementation of a TCP options parser
                 and does not benefit from the speed advantage generally
                 realised by calling to libtrace functions written in C through
                 python-libtrace.

    :param tcp: The TCP header to extract options from
    :type tcp: plt.tcp
    :returns: A mapping of option kinds to values
    :rtype: dict
    """

    optbytes = tcp.data[20:tcp.doff*4]
    opthash = {}

    # parse options in place
    cp = 0
    ncp = 0

    while cp < len(optbytes):
        # skip NOP
        if optbytes[cp] == TO_NOP:
            cp += 1
            continue
        # die on EOL
        if optbytes[cp] == TO_EOL:
            break

        # parse options length
        ncp = cp + optbytes[cp+1]

        # copy options data into hash
        # FIXME doesn't handle multiples
        opthash[optbytes[cp]] = optbytes[cp+2:ncp]

        # advance
        cp = ncp

    return opthash

class TCPChain(Chain):
    """
    This flow analysis chain records details of basic TCP behaviour in the
    flow record. It will determine when a 3WHS has completed and has simplified
    logic for determining when a TCP flow has completed.

    +----------------------+------+---------------------------------------------------------+
    | Field Name           | Type | Description                                             |
    +======================+======+=========================================================+
    | ``tcp_synflags_fwd`` | int  | SYN flags seen in the forward direction                 |
    +----------------------+------+---------------------------------------------------------+
    | ``tcp_synflags_rev`` | int  | SYN flags seen in the reverse direction                 |
    +----------------------+------+---------------------------------------------------------+
    | ``tcp_fin_fwd``      | bool | At least one FIN flag was seen in the forward direction |
    +----------------------+------+---------------------------------------------------------+
    | ``tcp_fin_rev``      | bool | At least one FIN flag was seen in the reverse direction |
    +----------------------+------+---------------------------------------------------------+
    | ``tcp_rst_fwd``      | bool | At least one RST flag was seen in the forward direction |
    +----------------------+------+---------------------------------------------------------+
    | ``tcp_rst_rev``      | bool | At least one RST flag was seen in the reverse direction |
    +----------------------+------+---------------------------------------------------------+
    | ``tcp_connected``    | bool | The 3WHS completed                                      |
    +----------------------+------+---------------------------------------------------------+
    """

    def new_flow(self, rec, ip): # pylint: disable=W0613
        """
        For a new flow, all fields will be initialised to ``False`` except
        ``tcp_synflags_*`` which will be set to ``None``.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IP or IPv6 packet that triggered the creation of a new
                   flow record
        :type ip: plt.ip or plt.ip6
        :return: Always ``True``
        :rtype: bool
        """

        rec['tcp_synflags_fwd'] = None
        rec['tcp_synflags_rev'] = None

        rec['tcp_fin_fwd'] = False
        rec['tcp_fin_rev'] = False
        rec['tcp_rst_fwd'] = False
        rec['tcp_rst_rev'] = False

        rec['tcp_connected'] = False

        return True

    def tcp(self, rec, tcp, rev):
        """
        Records basic TCP behaviour details.

        SYN Flags
            This will record the SYN flags observed in each direction. These will
            not be recorded again if there are futher segments in the flow with a
            SYN bit set, the first SYN observed wins.

        FIN and RST Flags
            If a segment has the FIN or RST flags, the relevant fields are set
            to true.

        3WHS
            If a SYN was observed in the forward direction, and a SYNACK in the
            reverse direction and the segment passed is an ACK in the forward
            direction then ``tcp_connected`` will be set to True.

        Flow Completion
            If a FIN has been observed in one direction and this segment
            contains a FIN in the other direction, a flow is considered
            complete. If a RST has been observed in either direction, a flow is
            considered complete.

        :param rec: the flow record
        :type rec: dict
        :param tcp: the TCP segment that was observed to be part of this flow
        :type ip: plt.tcp
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: True if flow should continue to be observed, False if the flow
                 should be passed on for merging (i.e. the flow is complete)
        :rtype: bool
        """

        if tcp.syn_flag:
            rec['tcp_synflags_rev' if rev else 'tcp_synflags_fwd'] = tcp.flags

        # This test is intended to catch the completion of the 3WHS.
        if (not rec['tcp_connected'] and rev == 0 and
                rec['tcp_synflags_fwd'] is not None and
                rec['tcp_synflags_rev'] is not None and
                rec['tcp_synflags_fwd'] & TCP_SYN == TCP_SYN and
                rec['tcp_synflags_rev'] & TCP_SA == TCP_SA and
                tcp.ack_flag):
            rec['tcp_connected'] = True

        if tcp.fin_flag and rev:
            rec['tcp_fin_fwd'] = True
        if tcp.fin_flag and not rev:
            rec['tcp_fin_rev'] = True
        if tcp.rst_flag and rev:
            rec['tcp_rst_rev'] = True
        if tcp.rst_flag and not rev:
            rec['tcp_rst_fwd'] = True

        return not ((rec['tcp_fin_fwd'] and rec['tcp_fin_rev']) or
                    rec['tcp_rst_fwd'] or rec['tcp_rst_rev'])
