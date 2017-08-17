"""
.. module:: pathspider.chains.traceroute
   :synopsis: A flow analysis chain for traceroute messages especially ismp messages

"""

from pathspider.chains.base import Chain
from pathspider.traceroute_send import INITIAL_SEQ
from pathspider.traceroute_send import INITIAL_PORT
from pip._vendor.progress import counter
import base64

ICMP4_TTLEXCEEDED = 11


#class ecn_traceChain(Chain):
#     """
#     This flow analysis chain records details of ICMP messages in
#     the flow record. It will record when a message of certain types have been
#     seen during a flow.
# 
#     +----------------------+--------+-------------------------------------------------------------+
#     | Field Name           | Type   | Meaning                                                     |
#     +======================+========+=============================================================+
#     | ``icmp_unreachable`` | bool   | An ICMP unreachable message was seen in the reverse         |
#     |                      |        | direction                                                   |
#     +----------------------+--------+-------------------------------------------------------------+
#     | ``icmp_ttlexceeded`` | bool   | An ICMP TTL exceeded message was seen in the reverse        |
#     |                      |        | direction                                                   |
#     +----------------------+--------+-------------------------------------------------------------|
#     """

class ECNChain_trace(Chain):

    
    def __init__(self):
        pass
    
    def box_info(ip, rev):
         
        
        #def ip4(self, rec, ip, rev):
             
            #"""Destination Stuff like IP, flags and hop number"""    
    #         if rev and ip.tcp:
    #              
    #             sequence = ip.tcp.ack_nbr             
    #                  
    #             """ECN-specific stuff like flags and DSCP"""
    #             ecn = ip.traffic_class
    #             flags = ip.tcp.data[13]                   
    #             payload_len = 9  #we don't care but needs to be bigger than 9 for ecn_flags to work properly
    #              
    #             [ece, cwr, ect1, ect2] = self.ecn_flags(ecn, flags, payload_len)      
    #             dscp = ecn >> 2                      
    #              
    #             """TCP SYN/ACK flags """
    #             if (flags >> 1) % 2:
    #                 syn = "SYN.set"
    #             else:
    #                 syn = "SYN.notset"     
    #             if (flags >> 4) % 2:
    #                 ack = "ACK.set"
    #             else:
    #                 ack = "ACK.notset"
    #              
    #             """Calculating final hop with sequence number """
    #             if rec['seq'] < sequence:
    #                 final_hop = sequence-1-INITIAL_SEQ #ACK_nbr -1 is final seq_number
    #                 rec['Destination'] = [str(ip.src_prefix), final_hop, ect1, ect2, ece, cwr, dscp, syn, ack]
    #                 rec['seq'] = sequence
             
        #"""If incoming packet has ICMP TTL exceeded message""" 
        if rev and ip.icmp:
            if ip.icmp.type == ICMP4_TTLEXCEEDED:# or ip.icmp.type == ICMP4_UNREACHABLE:
                    
              
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
                 
                [ece, cwr, ect1, ect2] = ECNChain_trace.ecn_flags(ecn, flags, payload_len) # !!!!!Why is self.ecn... not working?
              
        return [ece, cwr, ect1, ect2]
          
    def ecn_flags( ecn, flags, payload_len):
        
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
                
               
