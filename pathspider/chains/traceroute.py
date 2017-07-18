"""
.. module:: pathspider.chains.traceroute
   :synopsis: A flow analysis chain for traceroute messages especially ismp messages

"""

from pathspider.chains.base import Chain
from pathspider.traceroute_send import INITIAL_SEQ
from pathspider.traceroute_send import INITIAL_PORT
from pip._vendor.progress import counter
import base64

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
        
        #rec['Number of hops to reach destination'] = 0
        rec['ttl_exceeded'] = False
        #rec['Number of TCP packets sent'] = 0
        return True
    
    
    
    def ttl_in_hops(self,ttl_input):
        
        if ttl_input > 128:
            hops = 256 - ttl_input
        elif ttl_input > 64:
            hops = 129 - ttl_input
        elif ttl_input > 32:
            hops = 65 - ttl_input
        else:
            hops = 33 - ttl_input
        
        return hops
    
    def ip4(self, rec, ip, rev):
        
        if not rev and ip.tcp:
            ip_data = ip.data
            
            timeinit = ip.tcp.seconds
            sequence = ip.tcp.seq_nbr
            rec[sequence] = [timeinit, ip_data]
            
            
        if rev and ip.icmp:
            if ip.icmp.type == ICMP4_TTLEXCEEDED:# or ip.icmp.type == ICMP4_UNREACHABLE:
                rec['ttl_exceeded'] = True
             
                box_ip = str(ip.src_prefix)
             
                #rec['Destination'] = str(ip.icmp.payload.dst_prefix)
             
                """Packet arrival time"""
                time = ip.seconds
             
             
                """Identification of hop number via sequence number"""
                hopnumber = ip.icmp.payload.tcp.seq_nbr - (INITIAL_SEQ-1)        
             
                """length of payload that comes back to identify RFC1812-compliant routers"""
                pp = ip.icmp.payload.payload
             
#                 try:
#                     #tcpp = ip.icmp.payload.tcp.doff
#                     tcppp = ip.icmp.payload.tcp.option_numbers
#                     tcpp = str(tcppp[0])
#                 except TypeError:
#                         tcpp = 0

             
                payload = ip.icmp.payload.payload
                 
                data = ip.icmp.payload.data
     
                payload_len = len(pp)
                
                flags = -1
                
                if payload_len > 8:
                    flags = ip.icmp.payload.tcp.data[13]
                 
                ecn = ip.icmp.payload.traffic_class #% 4
             
             
                #try:
                    #print(base64.b64encode(pp))
                 #   print (pp.encode())
                #except ValueError:
                #    pass
                 
                rec[hopnumber] = [box_ip, time, payload_len, ecn, flags]
             
                return True
            
            
    
#     def tcp(self, rec, tcp, rev):
#     
#         """Check if received tcp package from destination matches the sent out one then get number of hops from
#         ack number, since this is one more than the received seq number which indicates the number of hops"""
#         
#         if not rev:
#             #rec['Number of TCP packets sent'] += 1
#             timeinit = tcp.seconds
#             sequence = tcp.seq_nbr
#             rec[sequence] = [timeinit, tcp.payload]
#             
#             #rec['Number of hops to reach destination'] = tcp.ack_nbr - (INITIAL_SEQ-2)
#         
#     
#     def icmp4(self, rec, ip, q, rev): # pylint: disable=no-self-use,unused-argument
#         """
#         Records ICMPv4 details.
# 
# 
#         :param rec: the flow record
#         :type rec: dict
#         :param ip: the IPv4 packet that was observed to be part of this flow
#                    and contained an ICMPv4 header
#         :type ip: plt.ip
#         :param q: the ICMP quotation of the packet that triggered this message
#                   (if any)
#         :type q: plt.ip
#         :param rev: ``True`` if the packet was in the reverse direction,
#                     ``False`` if in the forward direction
#         :type rev: bool
#         """
#             
#         
#         if rev and ip.icmp.type == ICMP4_TTLEXCEEDED:# or ip.icmp.type == ICMP4_UNREACHABLE:
#             rec['ttl_exceeded'] = True
#             
#             box_ip = str(ip.src_prefix)
#             
#             #rec['Destination'] = str(ip.icmp.payload.dst_prefix)
#             
#             """Packet arrival time"""
#             time = ip.seconds
#             
#             
#             """Identification of hop number via sequence number"""
#             hopnumber = ip.icmp.payload.tcp.seq_nbr - (INITIAL_SEQ-1)        
#             
#             """length of payload that comes back to identify RFC1812-compliant routers"""
#             pp = ip.icmp.payload.payload
#             
#             try:
#                 #tcpp = ip.icmp.payload.tcp.doff
#                 tcppp = ip.icmp.payload.tcp.option_numbers
#                 tcpp = str(tcppp[0])
#             except TypeError:
#                 tcpp = 0
#             
#             payload = ip.icmp.payload.payload
# 
#             payload_len = len(pp)
#             
#             ecn = ip.icmp.payload.traffic_class #% 4
#             
#             
#             #try:
#                 #print(base64.b64encode(pp))
#              #   print (pp.encode())
#             #except ValueError:
#             #    pass
#             
#             rec[hopnumber] = [box_ip, time, payload_len, ecn]
#             
#             return True
#         
#         """can i get the destination with this or similar???"""
#         
#         if rev and ip.icmp.type == ICMP4_UNREACHABLE:
#             
#             rec['22'] = [str(ip.src_prefix),0 ,0 ,0]
#             
#         return False

    def icmp6(self, rec, ip6, q, rev): # pylint: disable=no-self-use,unused-argument
        """
        Records ICMPv6 details.

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
        """

        
        if rev and ip6.icmp6.type == ICMP6_TTLEXCEEDED:
            rec['ttl_exceeded'] = True
            
            box_ip = str(ip6.src_prefix)
            hopnumber = ip6.icmp.payload.tcp.seq_nbr - (INITIAL_SEQ-1)
            #hopnumber = ip.icmp.payloaf.tcp.dst_port - (INITIAL_PORT-1)
            rec[hopnumber] = box_ip            
            return True
            
        return False
    
    