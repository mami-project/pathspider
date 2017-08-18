"""
.. module:: pathspider.chains.traceroute
   :synopsis: A flow analysis chain for traceroute messages especially ismp messages

"""

from pathspider.chains.base import Chain
from pathspider.traceroute_send import INITIAL_SEQ
from pathspider.traceroute_send import INITIAL_PORT
from pip._vendor.progress import counter
import base64
import logging

from straight.plugin import load

chain = load("pathspider.chains", subclasses=Chain)


# TODO PLUGIN works but which plugin do i want to make sth???????????????

chosen_chains = []

for abc in chain:
        if "_trace" in abc.__name__.lower():
            chosen_chains.append(abc)

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
         
         #rec['trace'] = False
         rec['seq'] = 0
         return True
        
    def ip4(self, rec, ip, rev):
         
         
        """Information about sent TCP messages like initial time and data"""
        if not rev and ip.tcp:
            data = ip.data
              
            timeinit = ip.tcp.seconds
            sequence = str(ip.tcp.seq_nbr)
            rec[sequence] = {'rtt': timeinit, 'data': data}
         
         
        """Destination Stuff like IP, flags and hop number"""    
        if rev and ip.tcp:
             
            sequence = ip.tcp.ack_nbr             
                 
            """ECN-specific stuff like flags and DSCP"""
            ecn = ip.traffic_class
            flags = ip.tcp.data[13]                   
            payload_len = 9  #we don't care but needs to be bigger than 9 for ecn_flags to work properly
             
            [ece, cwr, ect1, ect2] = self.ecn_flags(ecn, flags, payload_len)      
            dscp = ecn >> 2                      
             
            """TCP SYN/ACK flags """
            if (flags >> 1) % 2:
                syn = "SYN.set"
            else:
                syn = "SYN.notset"     
            if (flags >> 4) % 2:
                ack = "ACK.set"
            else:
                ack = "ACK.notset"
             
            """Calculating final hop with sequence number """
            if rec['seq'] < sequence:
                final_hop = sequence-1-INITIAL_SEQ #ACK_nbr -1 is final seq_number
                rec['Destination'] = {'from': str(ip.src_prefix),'hops': final_hop}#, ect1, ect2, ece, cwr, dscp, syn, ack}
                rec['seq'] = sequence
                
                if len(chosen_chains) > 0:
                    for c in chosen_chains:
                        
                        mic = getattr(c, "box_info")# if hasattr(c, box_info) #c.__name__
                        plugin_out = c.box_info(ip, rev)
                        
                    rec['Destination']['conditions'] = plugin_out
         
        """If incoming packet has ICMP TTL exceeded message"""    
        if rev and ip.icmp:
            if ip.icmp.type == ICMP4_TTLEXCEEDED:# or ip.icmp.type == ICMP4_UNREACHABLE:
                #rec['trace'] = True
              
                box_ip = str(ip.src_prefix)
              
                """Packet arrival time for calculation of rtt in merger"""
                time = ip.seconds
                           
                """Identification of hop number via sequence number"""
                hopnumber = str(ip.icmp.payload.tcp.seq_nbr - (INITIAL_SEQ-1))     
              
                """length of payload that comes back to identify RFC1812-compliant routers"""
                pp = ip.icmp.payload.payload
                payload_len = len(pp)
                 
                """payload data of returning packet for bitwise comparison in merger""" 
                data = ip.icmp.payload.data
          
                """ECN-specific stuff like flags and DSCP"""
                ecn = ip.icmp.payload.data[1]
                if payload_len > 8:
                    flags = ip.icmp.payload.tcp.data[13]
                else:
                    flags = 0 #we don't care
                
                rec[hopnumber] = {'from': box_ip, 'rtt': time, 'size': payload_len, 'data': data}
                
                """Additional 'conditions' info of other traceroutechain"""
                
                if len(chosen_chains) > 0:
                    for c in chosen_chains:
                        
                        mic = getattr(c, "box_info")# if hasattr(c, box_info) #c.__name__
                        plugin_out = c.box_info(ip, rev)
                        
                    rec[hopnumber]['conditions'] = plugin_out
 
        return True
    
      
    def ecn_flags(self, ecn, flags, payload_len):
        
        """TCP ECE and CWR flags"""
        if payload_len > 8:                   
            if (flags >> 6) % 2:
                ece = "ECE.set"
            else:
                ece = "ECE.notset"                    
            if (flags >> 7) % 2:
                cwr = "CWR.set"
            else:
                cwr = "CWR.notset"         
        else:
            ece = "ECE??"
            cwr = "CWR??"
                
                
        """IP ECT FLAGS"""                
        if (ecn % 2):
            ect1 = "ect1.set"
        else:
            ect1 = "ect1.notset"
        if (ecn >> 1) % 2:
            ect2 = "ect2.set"
        else: 
            ect2 = "ect2.notset"  
              
        return [ece, cwr, ect1, ect2]            
            
    def ip6(self, rec, ip, rev):
#         
#         if not rev and ip.tcp:
#             ip_data = ip.data
#              
#             timeinit = ip.tcp.seconds
#             sequence = ip.tcp.seq_nbr
#             rec[sequence] = [timeinit]
#             
#         if rev and ip.tcp:
#             
#             sequence = ip.tcp.seq_nbr
#             rec['Destination'] = str(ip.src_prefix)
#          
#          
#         """Trying to get TCP stuff from destination"""
#          
#             
#             
#         if rev and ip.icmp:
#             if ip.icmp.type == ICMP6_TTLEXCEEDED:# or ip.icmp.type == ICMP4_UNREACHABLE:
#                 rec['ttl_exceeded'] = True
#              
#                 box_ip = str(ip.src_prefix)
#              
#                 #rec['Destination'] = str(ip.icmp.payload.dst_prefix)
#              
#                 """Packet arrival time"""
#                 time = ip.seconds
#              
#              
#                 """Identification of hop number via sequence number"""
#                 hopnumber = ip.icmp.payload.tcp.seq_nbr - (INITIAL_SEQ-1)        
#              
#                 """length of payload that comes back to identify RFC1812-compliant routers"""
#                 pp = ip.icmp.payload.payload
#              
# #                 try:
# #                     #tcpp = ip.icmp.payload.tcp.doff
# #                     tcppp = ip.icmp.payload.tcp.option_numbers
# #                     tcpp = str(tcppp[0])
# #                 except TypeError:
# #                         tcpp = 0
# 
#              
#                 payload = ip.icmp.payload.payload
#                  
#                 data = ip.icmp.payload.data
#      
#                 payload_len = len(pp)
#                 
#                 flags = -1
#                 
#                 
#                 
#                 
#                 if payload_len > 8:
#                     flags = ip.icmp.payload.tcp.data[13]
#                     
#                     if (flags >> 6) % 2:
#                         ece = "ECE.set"
#                     else:
#                         ece = "ECE.notset"
#                         
#                     if (flags >> 7) % 2:
#                         cwr = "CWR.set"
#                     else:
#                         cwr = "CWR.notset"
#                         
#                 else:
#                     cwr = "ECE??"
#                     ece = "CWR??"
#                  
#                 ecn = ip.icmp.payload.traffic_class #% 4
#              
#              
#                 #try:
#                     #print(base64.b64encode(pp))
#                  #   print (pp.encode())
#                 #except ValueError:
#                 #    pass
#                  
#                 rec[hopnumber] = [box_ip, time, payload_len, ecn, ece, cwr]
#              
                 return True
#     
class PluggabbleTracerouteChain(Chain):
    @staticmethod
    def register_args(subparsers):
        raise NotImplementedError("Cannot register an abstract plugin")