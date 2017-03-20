"""
.. module:: pathspider.chains.tcp
   :synopsis: A flow analysis chain for ICMP messages and useful ICMP related
              constants

This module contains the ICMPChain flow analysis chain which can be used by
PATHspider's Observer for recording ICMPv4 [RFC792]_ and ICMPv6 [RFC4443]_
details.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

from pathspider.chains.base import Chain

#: ICMPv4 Message Type - Unreachable
ICMP4_UNREACHABLE = 3
#: ICMPv4 Message Type - TTL Exceeded
ICMP4_TTLEXCEEDED = 11

#: ICMPv6 Message Type - Unreachable
ICMP6_UNREACHABLE = 1
#: ICMPv6 Message Type - Time Exceeded
ICMP6_TTLEXCEEDED = 3

class ICMPChain(Chain):
    """
    This flow analysis chain records details of ICMP messages in
    the flow record. It will record when a message of certain types have been
    seen during a flow.

    +----------------------+--------+-------------------------------------------------------------+
    | Field Name           | Type   | Meaning                                                     |
    +======================+========+=============================================================+
    | ``icmp_unreachable`` | bool   | An ICMP unreachable message was seen in the reverse         |
    |                      |        | direction                                                   |
    +----------------------+--------+-------------------------------------------------------------+
    """

    def new_flow(self, rec, ip):
        """
        For a new flow, all fields will be initialised to ``False``.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IP or IPv6 packet that triggered the creation of a new
                   flow record
        :type ip: plt.ip or plt.ip6
        :return: Always ``True``
        :rtype: bool
        """

        rec['icmp_unreachable'] = False
        return True

    def icmp4(self, rec, ip, q, rev): # pylint: disable=no-self-use,unused-argument
        """
        Records ICMPv4 details.

        ICMPv4 Unreachable Messages
            Sets ``icmp_unreachable`` to ``True`` if an ICMP Unreachable
            message is seen in the reverse direction.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv4 packet that was observed to be part of this flow
                   and contained an ICMPv4 header
        :type ip: plt.ip
        :param q: the ICMP quotation of the packet that triggered this message
                  (if any)
        :type q: plt.ip
        :param rev: ``True`` if the packet was in the reverse direction,
                    ``False`` if in the forward direction
        :type rev: bool
        :return: ``False`` if an ICMP unreachable message has been observed,
                 otherwise ``True``
        :rtype: bool
        """

        if rev and ip.icmp.type == ICMP4_UNREACHABLE:
            rec['icmp_unreachable'] = True
        return not rec['icmp_unreachable']

    def icmp6(self, rec, ip6, q, rev): # pylint: disable=no-self-use,unused-argument
        """
        Records ICMPv6 details.

        ICMPv6 Unreachable Messages
            Sets ``icmp_unreachable`` to ``True`` if an ICMP Unreachable
            message is seen in the reverse direction.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv6 packet that was observed to be part of this flow
                   and contained an ICMPv6 header
        :type ip: plt.ip6
        :param q: the ICMP quotation of the packet that triggered this message
                  (if any)
        :type q: plt.ip
        :param rev: ``True`` if the packet was in the reverse direction,
                    ``False`` if in the forward direction
        :type rev: bool
        :return: ``False`` if an ICMP unreachable message has been observed,
                 otherwise ``True``
        :rtype: bool
        """

        if rev and ip6.icmp6.type == ICMP6_UNREACHABLE:
            rec['icmp_unreachable'] = True
        return not rec['icmp_unreachable']
