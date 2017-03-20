"""
.. module:: pathspider.chains.ecn
   :synopsis: A flow analysis chain for Explicit Congestion Notification

This module contains the ECNChain flow analysis chain which can be used by
PATHspider's Observer for recording Explicit Congestion Notification [RFC3168]_
details.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

from pathspider.chains.base import Chain
from pathspider.chains.tcp import TCP_SYN

class ECNChain(Chain):
    """
    This flow analysis chain records details of ECN markings in the IP header.

    +-------------------+------+----------------------------------------------------+
    | Field Name        | Type | Meaning                                            |
    +===================+======+====================================================+
    | ecn_ect0_syn_fwd  | bool | An ECT0 mark was seen in the forward direction     |
    |                   |      | on a TCP SYN packet                                |
    +-------------------+------+----------------------------------------------------+
    | ecn_ect1_syn_fwd  | bool | An ECT1 mark was seen in the forward direction     |
    |                   |      | on a TCP SYN packet                                |
    +-------------------+------+----------------------------------------------------+
    | ecn_ce_syn_fwd    | bool | An CE mark was seen in the forward direction       |
    |                   |      | on a TCP SYN packet                                |
    +-------------------+------+----------------------------------------------------+
    | ecn_ect0_data_fwd | bool | An ECT0 mark was seen in the forward direction     |
    |                   |      | on a TCP packet with a payload or a non-TCP packet |
    +-------------------+------+----------------------------------------------------+
    | ecn_ect1_data_fwd | bool | An ECT1 mark was seen in the forward direction     |
    |                   |      | on a TCP packet with a payload or a non-TCP packet |
    +-------------------+------+----------------------------------------------------+
    | ecn_ce_data_fwd   | bool | An CE mark was seen in the forward direction       |
    |                   |      | on a TCP packet with a payload or a non-TCP packet |
    +-------------------+------+----------------------------------------------------+
    | ecn_ect0_syn_rev  | bool | An ECT0 mark was seen in the reverse direction     |
    |                   |      | on a TCP SYN packet                                |
    +-------------------+------+----------------------------------------------------+
    | ecn_ect1_syn_rev  | bool | An ECT1 mark was seen in the reverse direction     |
    |                   |      | on a TCP SYN packet                                |
    +-------------------+------+----------------------------------------------------+
    | ecn_ce_syn_rev    | bool | An CE mark was seen in the reverse direction       |
    |                   |      | on a TCP SYN packet                                |
    +-------------------+------+----------------------------------------------------+
    | ecn_ect0_data_rev | bool | An ECT0 mark was seen in the reverse direction     |
    |                   |      | on a TCP packet with a payload or a non-TCP packet |
    +-------------------+------+----------------------------------------------------+
    | ecn_ect1_data_rev | bool | An ECT1 mark was seen in the reverse direction     |
    |                   |      | on a TCP packet with a payload or a non-TCP packet |
    +-------------------+------+----------------------------------------------------+
    | ecn_ce_data_rev   | bool | An CE mark was seen in the reverse direction       |
    |                   |      | on a TCP packet with a payload or a non-TCP packet |
    +-------------------+------+----------------------------------------------------+
    """

    def new_flow(self, rec, ip): # pylint: disable=unused-argument
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

        for d in ['fwd', 'rev']:
            for t in ['syn', 'data']:
                for f in ['ect0', 'ect1', 'ce']:
                    rec['ecn_{}_{}_{}'.format(f, t, d)] = False

        return True

    def ip4(self, rec, ip, rev):
        """
        Records ECN markings from an IPv4 header.

        ECN Marking
            If an ECT0, ECT1 or CE mark is seen in the IPv4 header, the relevant
            field will be set to ``True``.

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

        return self._ecn_extract(rec, ip, rev)

    def ip6(self, rec, ip, rev):
        """
        Records ECN markings from an IPv6 header.

        ECN Marking
            If an ECT0, ECT1 or CE mark is seen in the IPv6 header, the relevant
            field will be set to ``True``.

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

        return self._ecn_extract(rec, ip, rev)

    def _ecn_extract(self, rec, ip, rev):
        ECT_ZERO = 0x02
        ECT_ONE = 0x01
        ECT_CE = 0x03

        ipmark = None

        if ip.traffic_class & ECT_CE == ECT_ZERO:
            ipmark = 'ecn_ect0'
        if ip.traffic_class & ECT_CE == ECT_ONE:
            ipmark = 'ecn_ect1'
        if ip.traffic_class & ECT_CE == ECT_CE:
            ipmark = 'ecn_ce'

        if ipmark is not None:
            if ip.tcp and ip.tcp.flags & TCP_SYN == TCP_SYN:
                t = 'syn'
            else:
                t = 'data'
            d = 'rev' if rev else 'fwd'
            rec['{}_{}_{}'.format(ipmark, t, d)] = True

        return True
