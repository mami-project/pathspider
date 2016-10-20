
from pyroute2 import IPDB # pylint: disable=no-name-in-module

def interface_up(int):
    with IPDB() as ipdb:
        for interface in set(ipdb.interfaces.values()):
            if interface.ifname == int and interface.operstate == 'UP':
                return True
        return False
