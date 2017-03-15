
from pathspider.observer.base import Chain

class ECNChain(Chain):

    def new_flow(self, rec, ip): # pylint: disable=unused-argument
        fields = [
            'ecn_ect0_fwd',
            'ecn_ect1_fwd',
            'ecn_ce_fwd',
            'ecn_ect0_rev',
            'ecn_ect1_rev',
            'ecn_ce_rev'
        ]
    
        for field in fields:
            rec[field] = False
        return True
    
    def tcp(self, rec, ip, rev):
        ECT_ZERO = 0x02
        ECT_ONE = 0x01
        ECT_CE = 0x03
    
        if ip.traffic_class & ECT_CE == ECT_ZERO:
            rec['ecn_ect0_rev' if rev else 'ecn_ect0_fwd'] = True
        if ip.traffic_class & ECT_CE == ECT_ONE:
            rec['ecn_ect1_rev' if rev else 'ecn_ect1_fwd'] = True
        if ip.traffic_class & ECT_CE == ECT_CE:
            rec['ecn_ce_rev' if rev else 'ecn_ce_fwd'] = True
    
        return True
