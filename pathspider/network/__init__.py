
from pyroute2 import IPDB # pylint: disable=no-name-in-module

def interface_up(int):
    with IPDB() as ipdb:
        for interface in set(ipdb.interfaces.values()):
            if interface.ifname == int and interface.operstate == 'UP':
                return True
        return False

def ipv4_address(int):
    # Should return the IPv4 address of the interface
    pass

def ipv6_address(int):
    # Should return the IPv6 address of the interface
    pass

def ipv4_first_hop(int):
    # Should return the IPv4 address and MAC address of the first hop
    pass

def ipv6_first_hop(int):
    # Should return the IPv6 address and MAC address of the first hop
    pass

