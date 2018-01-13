"""
.. module:: pathspider.chains.dscp
   :synopsis: A flow analysis chain for UDP

This module contains the UDPChain flow analysis chain which can be used by
PATHspider's Observer for recording UDP details.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

from pathspider.chains.base import Chain

class UDPChain(Chain):
    """

    +---------------------------+------+---------------------------------------+
    | Field Name                | Type | Meaning                               |
    +===========================+======+=======================================+
    | ``udp_zero_checksum_fwd`` | bool | True if the last packet in the flow   |
    |                           |      | in the forward direction had the UDP  |
    |                           |      | checksum disabled (set to zero).      |
    +---------------------------+------+---------------------------------------+
    | ``udp_zero_checksum_rev`` | bool | True if the last packet in the flow   |
    |                           |      | in the reverse direction had the UDP  |
    |                           |      | checksum disabled (set to zero).      |
    +---------------------------+------+---------------------------------------+
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

        rec['udp_zero_checksum_fwd'] = None
        rec['udp_zero_checksum_rev'] = None
        return True

    def udp(self, rec, udp, rev):
        """
        Records details from UDP datagram about the UDP header.

        :param rec: the flow record
        :type rec: dict
        :param tcp: the UDP packet that was observed to be part of this flow
        :type ip: plt.udp
        :param rev: ``True`` if the packet was in the reverse direction, ``False`` if
                    in the forward direction
        :type rev: bool
        :return: Always ``True``
        :rtype: bool
        """

        rec['udp_zero_checksum_rev' if rev else 'udp_zero_checksum_fwd'] = udp.checksum == 0

        return True
