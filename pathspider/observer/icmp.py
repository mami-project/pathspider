
from pathspider.observer.base import Chain

ICMP_UNREACHABLE = 3

class ICMPChain(Chain):

    def new_flow(self, rec, ip):
        rec['icmp_unreachable'] = False
        return True

    def icmp4(self, rec, ip, q, rev):
        return self._icmp(rec, ip, q, rev)
 
    def _icmp(self, rec, ip, q, rev): # pylint: disable=W0613
        if rev and ip.icmp.type == ICMP_UNREACHABLE:
            rec['icmp_unreachable'] = True
        return not rec['icmp_unreachable']
