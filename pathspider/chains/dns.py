"""
.. module:: pathspider.chains.dns
   :synopsis: A flow analysis chain for the Domain Name System

This module contains the DNSChain flow analysis chain which can be used by
PATHspider's Observer for recording Domain Name System [RFC1035]_ details.

.. codeauthor:: Iain R. Learmonth <irl@fsfe.org>

"""

from pathspider.chains.base import Chain

class DNSChain(Chain):
    """
    This flow analysis chain records details from Domain Name System
    application data.

    +------------------------+------+-----------------------------------------+
    | Field Name             | Type | Meaning                                 |
    +========================+======+=========================================+
    | ``dns_response_valid`` | bool | The flow contained a valid DNS response |
    +------------------------+------+-----------------------------------------+
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

        rec['dns_response_valid'] = False

        return True

    def tcp(self, rec, tcp, rev):
        """
        Records DNS details from TCP segment.

        DNS Response
            If the packet contains a payload, an attempt is made to parse it
            and if successful the ``dns_response_valid`` field is set to ``True``
            if it was a response (not a query).

        :param rec: the flow record
        :type rec: dict
        :param tcp: the TCP packet that was observed to be part of this flow
        :type ip: plt.tcp
        :param rev: ``True`` if the packet was in the reverse direction, ``False`` if
                    in the forward direction
        :type rev: bool
        :return: ``False`` if a valid DNS response has been seen, otherwise ``True``
        :rtype: bool
        """

        if tcp.payload is not None:
            return self._dns_response(rec, tcp.payload, rev)
        else:
            return True

    def udp(self, rec, udp, rev):
        """
        Records DNS details from UDP datagram.

        DNS Response
            If the packet contains a payload, an attempt is made to parse it
            and if successful the ``dns_response_valid`` field is set to ``True``
            if it was a response (not a query).

        :param rec: the flow record
        :type rec: dict
        :param tcp: the UDP packet that was observed to be part of this flow
        :type ip: plt.udp
        :param rev: ``True`` if the packet was in the reverse direction, ``False`` if
                    in the forward direction
        :type rev: bool
        :return: ``False`` if a valid DNS response has been seen, otherwise ``True``
        :rtype: bool
        """

        return self._dns_response(rec, udp.payload, rev)

    def _dns_response(self, rec, payload, rev):
        try:
            from pldns import ldns # pylint: disable=E0611

            if rev is True:
                dns = ldns(payload)
                if dns.is_ok():
                    if dns.is_response:
                        rec['dns_response_valid'] = True
        except ImportError:
            raise RuntimeError("python-libtrace is not installed! "
                               "Cannot dissect DNS!")
        except ValueError:
            pass # Wasn't a DNS payload
        return not rec['dns_response_valid']
