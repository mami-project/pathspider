
from pathspider.observer.base import Chain


ICMP_UNREACHABLE = 3
ICMP_TTLEXCEEDED = 11

ICMP6_UNREACHABLE = 1
ICMP6_TTLEXCEEDED = 3

class ICMPChain(Chain):

    def new_flow(self, rec, ip):
        rec['icmp_unreachable'] = False
        return True

    def icmp4(self, rec, ip, q, rev): # pylint: disable=W0613
        if rev and ip.icmp.type == ICMP_UNREACHABLE:
            rec['icmp_unreachable'] = True
        return not rec['icmp_unreachable']

    def icmp6(self, rec, ip6, q, rev): # pylint: disable=W0613
        if rev and ip6.icmp6.type == ICMP6_UNREACHABLE:
            rec['icmp_unreachable'] = True
        return not rec['icmp_unreachable']
