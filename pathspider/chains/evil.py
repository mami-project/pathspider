"""
.. module:: pathspider.chains.evilbit
   :synopsis: A flow analysis chain for EvilBit

This module contains the EvilChain analysis chain which can be used by
PATHspider's Observer for recording Evil Bit connectivity [RFC3514] details.

"""

from pathspider.chains.tcp import TCP_SYN
from pathspider.chains.base import Chain

class EvilChain(Chain):

    """
    
    +-----------------------+------+------------------------------------------------+
    | Field Name            | Type | Meaning                                        |
    +=======================+======+================================================+
    | ``evilbit_syn_fwd``   | bool | True if the evil bit was set in the IP header  |
    |                       |      | for a TCP SYN packet in the forward direction, |
    |                       |      | false otherwise                                |
    +-----------------------+------+------------------------------------------------+
    | ``evilbit_syn_fwd``   | bool | True if the evil bit was set in the IP header  |
    |                       |      | for a TCP SYN packet in the reverse direction, |
    |                       |      | false otherwise                                |
    +-----------------------+------+------------------------------------------------+
    | ``evilbit_data_fwd``  | bool | True if the evil bit was set in the IP header  |
    |                       |      | for a non-TCP packet in the forward direction, |
    |                       |      | false otherwise                                |
    +-----------------------+------+------------------------------------------------+
    | ``evilbit_data_rev``  | bool | True if the evil bit was set in the IP header  |
    |                       |      | for a non-TCP packet in the  reverse direction,|
    |                       |      | false otherwise                                |
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

        rec['evilbit_syn_fwd'] = None
        rec['evilbit_syn_rev'] = None
        rec['evilbit_data_fwd'] = None
        rec['evilbit_data_rev'] = None
        return True
    
    def ip4(self, rec, ip, rev):
        """
        Records evil bit markings from an IPv4 header.

        Evil Bit Marking
            For either TCP_SYN packets or non-TCP or TCP with payload packets
            the relevant field will record whether the Evil Bit was set.

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
        evil = ip.has_rf
            
        if ip.tcp:
            if ip.tcp.flags & TCP_SYN == TCP_SYN:
                rec['evilbit_syn_rev' if rev else 'evilbit_syn_fwd'] = evil
                return True
            if ip.tcp.payload is None:
                return True
            
        # If not TCP or TCP non-SYN
        data_key = 'evilbit_data_rev' if rev else 'evilbit_data_fwd'
        if rec[data_key] is None:
            rec[data_key] = evil
            return True


