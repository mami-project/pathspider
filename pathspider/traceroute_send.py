from scapy.all import *

def send_pkts(ttl_input,dip):
    
    """Sending packet with a sufficient big payload or else the observer.py will give
        back an error for payload being too small"""
    
    hops_add = 3        # buffer for additional hops
    
    # abklären erster hop und 256- oder 255-
    
    # check for possible initial max hops
    if ttl_input > 128:
        hops = 256 - ttl_input + hops_add
    elif ttl_input > 64:
        hops = 129 - ttl_input + hops_add
    elif ttl_input > 32:
        hops = 65 - ttl_input + hops_add
    else:
        hops = 33 - ttl_input + hops_add
  
        
    for i in range(hops):
        send(IP(ttl=i,dst = dip)/ICMP()/"XXXXXXXXXXXXXXXXXXXXX")
    
    
    return


def send_pkt(ttl_input,dip):
    
    """Sending packet with a sufficient big payload or else the observer.py will give
        back an error for payload being too small"""
    
   
    send(IP(ttl=ttl_input,dst = dip)/ICMP()/"XXXXXXXXXXXXXXXXXXXXX")
    
    
    return

#send_pkt(30,"172.217.18.99")

send_pkts(54,"172.217.18.99")   #54 is ttl i became back from destination