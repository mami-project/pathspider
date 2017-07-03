from scapy.all import *
import time
from pathspider.base import QUEUE_SIZE


INITIAL_PORT = 10000
INITIAL_SEQ = 10000

def send_pkts(ttl_input,dip,src,outqueue):
    
    """Send TCP packet with increasing TTL for every hop to destination"""
    
    hops_add = 3        # buffer for additional hops
    
    time.sleep(2)   #wait short time to guarantee that observer finished setting up
    
    # check for possible initial max hops
    if ttl_input > 128:
        hops = 256 - ttl_input + hops_add
    elif ttl_input > 64:
        hops = 129 - ttl_input + hops_add
    elif ttl_input > 32:
        hops = 65 - ttl_input + hops_add
    else:
        hops = 33 - ttl_input + hops_add
  
    for j in range(src):    #repeating with src different flows
        for i in range(hops):
            send(IP(ttl=i,dst = dip)/TCP(seq=(INITIAL_SEQ-1+i),sport = (INITIAL_PORT-1+j)))
            outqueue.put(time.clock())
        #send(IP(ttl=i,dst = dip)/TCP(sport = (INITIAL_PORT-1+i)))
    
    return


def send_pkt(ttl_input,dip):
    """Send one packet for testing purpose"""
   
    send(IP(ttl=ttl_input,dst = dip)/TCP(seq=INITIAL_SEQ))
    
    
    return

#send_pkt(2,"172.217.18.99")

#send_pkts(45,"172.217.18.99")   #54 is TTL that came back from destination