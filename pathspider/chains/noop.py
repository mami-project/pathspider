"""
.. module:: pathspider.chains.noop
   :synopsis: A flow observer chain that does nothing

This module contains the NoOpChain flow analysis chain which can be used by
PATHspider's Observer.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

from pathspider.chains.base import Chain

class NoOpChain(Chain):
    """
    This flow analysis chain does not perform any analysis and is present here
    for the purpose of documentation and testing.
    """

    def new_flow(self, rec, ip): # pylint: disable=unused-argument
        """
        This function is called for every new flow to initialise a flow record
        with the fields that will be used by this chain. It is recommended to
        initialise all fields to None until other functions have set values for
        them to make clear which fields are set by this chain and to avoid key
        errors later.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IP or IPv6 packet that triggered the creation of a new
                   flow record
        :type ip: plt.ip or plt.ip6
        :return: True if flow should be kept, False if flow should be discarded
        :rtype: bool
        """
        return True

    def ip4(self, rec, ip, rev): # pylint: disable=unused-argument
        """
        This function is called for every new IPv4 packet seen. It can be used
        to record details for fields present in the IPv4 header.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv4 packet that was observed to be part of this flow
        :type ip: plt.ip
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: True if flow should continue to be observed, False if the flow
                 should be passed on for merging (i.e. the flow is complete)
        :rtype: bool
        """

        return True

    def ip6(self, rec, ip6, rev): # pylint: disable=unused-argument
        """
        This function is called for every new IPv6 packet seen. It can be used
        to record details for fields present in the IPv6 header.

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv6 packet that was observed to be part of this flow
        :type ip: plt.ip6
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: True if flow should continue to be observed, False if the flow
                 should be passed on for merging (i.e. the flow is complete)
        :rtype: bool
        """

        return True

    def icmp4(self, rec, ip, q, rev): # pylint: disable=unused-argument
        """
        This function is called for every new ICMPv4 packet seen. It can be
        used to record details for fields present in the ICMPv4 header or
        quotation.

        .. note:: The IP header is passed as the argument, not the ICMP header
                  as it may be desirable to access fields in the IP header, for
                  instance to determine the router or host that sent the ICMP
                  message

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv4 packet that was observed to be part of this flow
                   and contained an ICMPv4 header
        :type ip: plt.ip
        :param q: the ICMP quotation of the packet that triggered this message
                  (if any)
        :type q: plt.ip
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: True if flow should continue to be observed, False if the flow
                 should be passed on for merging (i.e. the flow is complete)
        :rtype: bool
        """

        return True

    def icmp6(self, rec, ip6, q, rev): # pylint: disable=unused-argument
        """
        This function is called for every new ICMPv6 packet seen. It can be
        used to record details for fields present in the ICMPv6 header or
        quotation.

        .. note:: The IP header is passed as the argument, not the ICMP header
                  as it may be desirable to access fields in the IP header, for
                  instance to determine the router or host that sent the ICMP
                  message

        :param rec: the flow record
        :type rec: dict
        :param ip: the IPv6 packet that was observed to be part of this flow
                   and contained an ICMPv6 header
        :type ip: plt.ip6
        :param q: the ICMP quotation of the packet that triggered this message
                  (if any)
        :type q: plt.ip6
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: True if flow should continue to be observed, False if the flow
                 should be passed on for merging (i.e. the flow is complete)
        :rtype: bool
        """

        return True

    def tcp(self, rec, tcp, rev): # pylint: disable=unused-argument
        """
        This function is called for every new TCP packet seen. It can be used
        to record details for fields present in the TCP header.

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

        return True

    def udp(self, rec, udp, rev): # pylint: disable=unused-argument
        """
        This function is called for every new UDP packet seen. It can be used
        to record details for fields present in the UDP header.

        :param rec: the flow record
        :type rec: dict
        :param tcp: the UDP segment that was observed to be part of this flow
        :type ip: plt.udp
        :param rev: True if the packet was in the reverse direction, False if
                    in the forward direction
        :type rev: bool
        :return: True if flow should continue to be observed, False if the flow
                 should be passed on for merging (i.e. the flow is complete)
        :rtype: bool
        """

        return True
