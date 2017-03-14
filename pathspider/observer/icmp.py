
ICMP_UNREACHABLE = 3

class ICMPChain:

    def new_flow(self, rec, ip):
        rec['icmp_unreachable'] = False
        return True

    def icmp4(self, rec, ip, q, rev):
        return self._icmp(rec, ip, q, rev)
 
    def _icmp(self, rec, ip, q, rev):
        if rev and ip.icmp.type == ICMP_UNREACHABLE:
            rec['icmp_unreachable'] = True
        return not rec['icmp_unreachable']
