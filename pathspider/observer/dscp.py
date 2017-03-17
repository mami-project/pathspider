
from pathspider.observer.base import Chain
from pathspider.observer.tcp import TCP_SYN

class DSCPChain(Chain):

    def new_flow(self, rec, ip):
        rec['dscp_mark_syn_fwd'] = None
        rec['dscp_mark_syn_rev'] = None
        rec['dscp_mark_data_fwd'] = None
        rec['dscp_mark_data_rev'] = None
        return True

    def ip4(self, rec, ip, rev):
        return self._dscp_extract(rec, ip, rev)

    def ip6(self, rec, ip, rev):
        return self._dscp_extract(rec, ip, rev)

    def _dscp_extract(self, rec, ip, rev):
        tos = ip.traffic_class
        dscp = tos >> 2
    
        if ip.tcp:
            if ip.tcp.flags & TCP_SYN == TCP_SYN:
                rec['dscp_mark_syn_rev' if rev else 'dscp_mark_syn_fwd'] = dscp
                return True
            if ip.tcp.payload is None:
                return True
    
        # If not TCP or TCP non-SYN
        data_key = 'dscp_mark_data_rev' if rev else 'dscp_mark_data_fwd'
        rec[data_key] = rec[data_key] or dscp
        return True
