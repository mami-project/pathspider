
from pyroute2 import IPDB # pylint: disable=no-name-in-module

def interface_up(int):
    with IPDB() as ipdb:
        for interface in set(ipdb.interfaces.values()):
            if interface.ifname == int and interface.operstate == 'UP':
                return True
        return False
    
def ipv4_address(int):
    with IPDB() as ipdb:
        addrset = [x[0] for x in ipdb.interfaces[int].ipaddr if '.' in x[0]]
        if len(addrset) > 0:
            # Should return the first IPv4 address of the interface...if there are any
            return addrset[0]

def ipv6_address(int):
    with IPDB() as ipdb:
        addrset = [x[0] for x in ipdb.interfaces[int].ipaddr if ':' in x[0] and not x[0].startswith('fe')]
        if len(addrset) > 0:
            # Should return the first IPv6 address of the interface...if there are any
            return addrset[0]
