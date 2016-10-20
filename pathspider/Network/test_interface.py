from pyroute2 import IPDB

def test_interface(int):
    ip = IPDB()
    for interface in set(ip.interfaces.values()):
        if interface.ifname == int and interface.operstate == 'UP':
            ip.release()
            return true
    ip.release()
    return false
