from scapy.all import *
import time
import queue
import logging
#from pathspider.base import Spider
from pathspider.base import QUEUE_SIZE
from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.base import QUEUE_SLEEP

INITIAL_PORT = 10000
INITIAL_SEQ = 10000

class traceroute():
    
    def __init__(self):
        logging.getLogger("traceroute")
        
    def sender(self, ipqueue, flows):
        """Send TCP packet with increasing TTL for every hop to destination"""
    
        #TODO integrate src for number of flows

        logger = logging.getLogger('sender')
        
        src = flows
        logger.info("Sender started")
        while True:
            try:
                info = ipqueue.get_nowait()
            except queue.Empty:
                time.sleep(QUEUE_SLEEP)
            else:
                if info == SHUTDOWN_SENTINEL:
                    break
                else:
                    dip = info['dip']
                    hop = info['hops']
                    if hop > 50:
                        ttl = self._ttl_to_hops(hop)
                    else:
                        ttl = hop           
                    for j in range(src):    #repeating with src different flows  
                        for i in range(ttl):                   
                            if ':' in dip: #IPv6
                                send(IPv6(hlim=(i+1), tc=0,dst = dip)/TCP(seq=(INITIAL_SEQ+i),sport = (INITIAL_PORT+j), flags = 0xc2), verbose=0)
                            else:
                                send(IP(ttl=(i+1),dst = dip, tos = 0x00)/TCP(seq=(INITIAL_SEQ+i),sport = (INITIAL_PORT+j), flags = 0xc2), verbose=0)    #inter=0.1 for pause between packets
                        logger.info(("Sending flow %u of %s finished "), (j+1), dip)
                        
    def _ttl_to_hops(self, ttl_input):
        offset = 5  #buffer
         
        if ttl_input > 128:
            hops = 256 - ttl_input
        elif ttl_input > 64:
            hops = 129 - ttl_input
        else:
            hops = 65 - ttl_input
        
        hops = hops + offset
         
        return hops
        
    def trace_merger(self, tracemergequeue, traceoutqueue):
        logger = logging.getLogger('merger')
        while True:  
            res = tracemergequeue.get()
            if res == SHUTDOWN_SENTINEL:
                logger.info("merger shutdown")
                traceoutqueue.put(SHUTDOWN_SENTINEL)
                break          
            final = {}
            if res['trace'] == True:
                for entry in res.copy():
                    """Check for special entries that are needed in the output"""
                    if entry == 'dip':
                        final['dip'] = res[entry]
                    if entry == 'sip':
                        final['sip'] = res[entry]
                    if entry == 'Destination':
                        final['Destination'] = res['Destination']
                    
                    if entry.isdigit(): 
                        for entry2 in res.copy(): 
                            if entry2.isdigit():
                                if (int(entry)+INITIAL_SEQ-1) == int(entry2):  #comparing sequencenumber of upstream entry2 with hopnumber of downstream entry
                                    """RTT calculation"""
                                    rtt= (res[entry]['rtt']- res[entry2]['rtt'])*1000
                                    res[entry]['rtt'] = round(rtt,3)
                              
                                    """bytearray comparison """
                                    diff = bytearray()
                                    options = False                                                        
                                    off = []
                                    # length comparison
                                    length = int(len(res[entry]['data']))
                                    if len(res[entry]['data']) > len(res[entry2]['data']):
                                        length = int(len(res[entry2]['data']))
                                        options = True
                                    else:
                                        length = int(len(res[entry]['data']))
                                    #Actual bytewise comparison
                                    for i in range(length):
                                        bts = res[entry]['data'][i]^res[entry2]['data'][i]
                                        diff = diff + bts.to_bytes(1, byteorder='big')
                                        if bts != 0:# and i != 8 and i != 10 and i != 11:  #check for differences beside ttl and checksum
                                            off.append("%d: %d" % (i, bts))
                                    if options == True:
                                        off.append('options') 
                                    res[entry]['data'] = str(off)   
                                    final[entry] = res[entry]
                                    del res[entry2]
                                    
            # remove sequence number entries that have not been used                
            for entrytest in res.copy():
                try:
                    if int(entrytest) > 100:
                        del res[entrytest]
                except ValueError:
                    pass
                         
            traceoutqueue.put(final)