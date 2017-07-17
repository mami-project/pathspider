from scapy.all import *
import time
import queue
import logging
from pathspider.base import QUEUE_SIZE
from pathspider.base import SHUTDOWN_SENTINEL


INITIAL_PORT = 10000
INITIAL_SEQ = 10000

def send_pkts(hops,src,inqueue):
    
    """Send TCP packet with increasing TTL for every hop to destination"""
    
    logger = logging.getLogger("sender")

    
    hops_add = 3        # buffer for additional hops
    
    time.sleep(2)   #wait short time to guarantee that observer finished setting up
    
    # check for possible initial max hops
    #if ttl_input > 128:
     #   hops = 256 - ttl_input + hops_add
    #elif ttl_input > 64:
     #   hops = 129 - ttl_input + hops_add
    #elif ttl_input > 32:
     #   hops = 65 - ttl_input + hops_add
    #else:
     #   hops = 33 - ttl_input + hops_add
     
    while True:
    
        dip = inqueue.get()
        
        if dip == SHUTDOWN_SENTINEL:
            break
        else:
            for j in range(src):    #repeating with src different flows  
                for i in range(hops):
                    send(IP(ttl=(i+1),dst = dip, tos = 0x29)/TCP(seq=(INITIAL_SEQ+i),sport = (INITIAL_PORT+j)), verbose=0)
                    time.sleep(0.1)    
                time.sleep(0.25)
                logger.info(("Sending flow %u of %s finished "), (j+1), dip)

    
    return


def send_pkt(ttl_input,dip):
    """Send one packet for testing purpose"""
   
    send(IP(ttl=ttl_input,dst = dip)/TCP(seq=INITIAL_SEQ))
    
    
    return
