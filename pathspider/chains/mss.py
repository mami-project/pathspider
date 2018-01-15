"""
.. module:: pathspider.chains.tcp
   :synopsis: A flow analysis chain for TCP Maximum Segment Size

This module contains the MSSChain flow analysis chain which can be used by
PATHspider's Observer for recording TCP Maximum Segment Size details.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

from pathspider.chains.base import Chain
from pathspider.chains.tcp import tcp_options
from pathspider.chains.tcp import TO_MSS

class MSSChain(Chain):
    """
    This flow analysis chain records details of the TCP Maximum Segment Size
    (MSS) option in the flow record. It will determine the length and value of
    the field if present in SYN packets.

    +------------------+--------+-----------------------------------------------------------------+
    | Field Name       | Type   | Meaning                                                         |
    +==================+========+=================================================================+
    | ``mss_len_fwd``  | int    | Length of the MSS option field including kind and length in the |
    |                  |        | forward direction.                                              |
    +------------------+--------+-----------------------------------------------------------------+
    | ``mss_len_rev``  | int    | Length of the MSS option field including kind and length in the |
    |                  |        | reverse direction.                                              |
    +------------------+--------+-----------------------------------------------------------------+
    | ``mss_value_fwd``| int    | Value of the MSS option field in the forward direction.         |
    +------------------+--------+-----------------------------------------------------------------+
    | ``mss_value_rev``| int    | Value of the MSS option field in the reverse direction.         |
    +------------------+--------+-----------------------------------------------------------------+
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

        rec['mss_len_fwd'] = None
        rec['mss_len_rev'] = None
        rec['mss_value_fwd'] = None
        rec['mss_value_rev'] = None

        return True

    def tcp(self, rec, tcp, rev): # pylint: disable=unused-argument
        """
        Records TCP Maximum Segment Size Details.

        TCP Maximum Segment Size
            The TCP options will be parsed for the MSS option for all SYN
            packets.  If the option is found, the length and value for the
            option will be recorded in the flow.

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

        opts = tcp_options(tcp)

        if TO_MSS in opts:
            mss = bytes(opts[TO_MSS])
            rec['mss_len_' + ('rev' if rev else 'fwd')] = len(mss) + 2
            rec['mss_value_' + ('rev' if rev else 'fwd')] = int.from_bytes(mss, byteorder="big")

        # tell observer to keep going
        return True
