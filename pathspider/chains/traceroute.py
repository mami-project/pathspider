"""
.. module:: pathspider.chains.traceroute
   :synopsis: A flow analysis chain for traceroute messages especially ismp messages

"""

from pathspider.chains.base import Chain

#: ICMPv4 Message Type - Unreachable
ICMP4_UNREACHABLE = 3
#: ICMPv4 Message Type - TTL Exceeded
ICMP4_TTLEXCEEDED = 11
#: ICMPv4 Message Type - Source Quench
ICMP4_SOURCEQUENCH = 4
#: ICMPv4 Message Type - Redirect Message
ICMP4_REDIRECTMSG = 5
#: ICMPv4 Message Type - Parameter Problem: Bad IP Header
ICMP4_BADIP = 12
#: ICMPv4 Echo Reply


#: ICMPv6 Message Type - Unreachable
ICMP6_UNREACHABLE = 1
#: ICMPv6 Message Type - Time Exceeded
ICMP6_TTLEXCEEDED = 3
#: ICMPv6 Message Type - Packet Too Big
ICMP6_PKTTOOBIG = 2
#: ICMPv6 Message Type - Parameter Problem
ICMP6_BADIP = 4

class tracerouteChain(Chain):
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
    | ``icmp_ttlexceeded`` | bool   | An ICMP TTL exceeded message was seen in the reverse        |
    |                      |        | direction                                                   |
    +----------------------+--------+-------------------------------------------------------------|
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
        rec['icmp_ttl_exceeded'] = False
        rec['ip_ttl'] = 0
        #rec['sip_origin'] = 0
        #rec['dip_origin'] = 0
        #rec['icmp_dip'] = 0
        rec['ttlexceeded from ip'] = 0  # ip that sent back the ttl exceeded icmp message
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
        :return: ``True``
        :rtype: bool
        """
        
        # TTL of received package
        if rev:
            rec['ip_ttl'] = ip.ttl
            #rec['icmp_dip'] = str(ip.dst_prefix)
            rec['received icmp type'] = ip.icmp.type
            

            
        else:
            rec['sent icmp type'] = ip.icmp.type
            
        
        #OR kann man so nicht machen
        #if rev and ip.icmp.type == (ICMP4_UNREACHABLE or ICMP4_TTLEXCEEDED or ICMP4_SOURCEQUENCH or ICMP4_REDIRECTMSG or ICMP4_BADIP):
         #   print (ip.icmp.payload)
        
        if rev and ip.icmp.type == ICMP4_UNREACHABLE:
            rec['icmp_unreachable'] = True
        
        # when icmp message of type TTL then the encapsulated IP-header can be read out
        if rev and ip.icmp.type == ICMP4_TTLEXCEEDED:
            rec['icmp_ttl_exceeded'] = True
            rec['ttlexceeded from ip'] = str(ip.src_prefix)
            #rec['original_ttl'] = ip.icmp.payload.ttl
            #rec['dip_origin'] = str(ip.icmp.payload.dst_prefix)
            #rec['sip_origin'] = str(ip.icmp.payload.src_prefix)
        
        
        
        return True

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
        if rev and ip6.icmp6.type == ICMP6_TTLEXCEEDED:
            rec['icmp_ttl_expired'] = True
        return True