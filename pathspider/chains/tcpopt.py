"""
.. module:: pathspider.chains.tcp
   :synopsis: A flow analysis chain for TCP options (timestamp, Window Scaling, SACK)

This module contains the TCPOptChain flow analysis chain which can be used by
PATHspider's Observer for recording the presentent of the TCP TS, WS, and SACK options.

.. codeauthor:: Mirja Kuehlewind <mirja.kuehlewind@tik.ee.ethz.ch>

"""

from pathspider.chains.base import Chain
from pathspider.chains.tcp import tcp_options
from pathspider.chains.tcp import TO_SACKOK
from pathspider.chains.tcp import TO_TS
from pathspider.chains.tcp import TO_WS

class TCPOptChain(Chain):
    """
    This flow analysis chain records details of the TCP Maximum Segment Size
    (MSS) option in the flow record. It will determine the length and value of
    the field if present in SYN packets.

    +----------------+--------+------------------------------------------------------------------+
    | Field Name     | Type   | Meaning                                                          |
    +================+========+==================================================================+
    | ``tcpopt_ts``  | bool   | Indicates if the timestamp option is present in the SYN/ACK.     |
    +----------------+--------+------------------------------------------------------------------+
    | ``tcpopt_ws``  | bool   | Indicates if the Window Scaling option is present in the SYN/ACK.|
    +----------------+--------+------------------------------------------------------------------+
    | ``tcpopt_sack``| bool   | Indicates if the Sack option is present in the SYN/ACK.          |
    +----------------+--------+------------------------------------------------------------------+
    """

    def new_flow(self, rec, ip):
        """
        For a new flow, all fields will be initialised to ``None``.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IP or IPv6 packet that triggered the creation of a new
                   flow record
        :type ip: plt.ip or plt.ip6
        :return: Always ``True``
        :rtype: bool
        """

        rec['tcpopt_ts'] = None
        rec['tcpopt_ws'] = None
        rec['tcpopt_sack'] = None

        return True

    def tcp(self, rec, tcp, rev): # pylint: disable=unused-argument,no-self-use
        """
        Records if TCP option (TS, WS, SACK) are present in the SYN/ACK.

        :param rec: the flow record
        :type rec: dict
        :param tcp: the TCP segment that was observed to be part of this flow
        :type ip: plt.tcp
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: Always True
        :rtype: bool
        """

        # Shortcut non-SYN
        if not tcp.syn_flag:
            return True

        # Only look at reverse path for SYN/ACK
        if not rev:
            return True

        opts = tcp_options(tcp)

        if TO_TS in opts:
            rec['tcpopt_ts'] = True
        if TO_WS in opts:
            rec['tcpopt_ws'] = True
        if TO_SACKOK in opts:
            rec['tcpopt_sack'] = True

        # tell observer to keep going
        return True
