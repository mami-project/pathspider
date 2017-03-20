"""
.. module:: pathspider.chains.dscp
   :synopsis: A flow analysis chain for Differentiated Services

This module contains the DSCPChain flow analysis chain which can be used by
PATHspider's Observer for recording Differentiated Services [RFC2474]_ details.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

from pathspider.chains.base import Chain
from pathspider.chains.tcp import TCP_SYN

class DSCPChain(Chain):
    """
    This flow analysis chain records details of the Differentiated Services
    Field in the IP header.

    +-----------------------+------+------------------------------------------------+
    | Field Name            | Type | Meaning                                        |
    +=======================+======+================================================+
    | ``dscp_mark_syn_fwd`` | int  | The value of the Differentiated Services       |
    |                       |      | codepoint seen on a TCP SYN packet in the      |
    |                       |      | forward direction                              |
    +-----------------------+------+------------------------------------------------+
    | ``dscp_mark_syn_fwd`` | int  | The value of the Differentiated Services       |
    |                       |      | codepoint seen on a non-TCP packet or a TCP    |
    |                       |      | packet with a payload in the forward direction |
    +-----------------------+------+------------------------------------------------+
    | ``dscp_mark_syn_rev`` | int  | The value of the Differentiated Services       |
    |                       |      | codepoint seen on a TCP SYN packet in the      |
    |                       |      | reverse direction                              |
    +-----------------------+------+------------------------------------------------+
    | ``dscp_mark_syn_rev`` | int  | The value of the Differentiated Services       |
    |                       |      | codepoint seen on a non-TCP packet or a TCP    |
    |                       |      | packet with a payload in the reverse direction |
    +-----------------------+------+------------------------------------------------+
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

        rec['dscp_mark_syn_fwd'] = None
        rec['dscp_mark_syn_rev'] = None
        rec['dscp_mark_data_fwd'] = None
        rec['dscp_mark_data_rev'] = None
        return True

    def ip4(self, rec, ip, rev):
        """
        Records DSCP markings from an IPv4 header.

        DSCP Marking
            For the first TCP SYN packet and the first non-TCP packet or TCP
            packet with a payload, the DSCP value will be recorded in the
            relevant field.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv4 packet that was observed to be part of this flow
        :type ip: plt.ip
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: Always ``True``
        :rtype: bool
        """

        return self._dscp_extract(rec, ip, rev)

    def ip6(self, rec, ip, rev):
        """
        Records DSCP markings from an IPv6 header.

        DSCP Marking
            For the first TCP SYN packet and the first non-TCP packet or TCP
            packet with a payload, the DSCP value will be recorded in the
            relevant field.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv6 packet that was observed to be part of this flow
        :type ip: plt.ip6
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: Always ``True``
        :rtype: bool
        """

        return self._dscp_extract(rec, ip, rev)

    def _dscp_extract(self, rec, ip, rev):
        tos = ip.traffic_class
        dscp = tos >> 2
    
        if ip.tcp:
            if ip.tcp.flags & TCP_SYN == TCP_SYN:
                rec['dscp_mark_syn_rev' if rev else 'dscp_mark_syn_fwd'] = dscp
                return True
            if ip.tcp.payload is None:
                return True
    
        # If not TCP or TCP non-SYN
        data_key = 'dscp_mark_data_rev' if rev else 'dscp_mark_data_fwd'
        rec[data_key] = rec[data_key] or dscp
        return True
