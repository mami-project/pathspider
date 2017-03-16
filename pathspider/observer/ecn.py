
from pathspider.observer.base import Chain
from pathspider.observer.tcp import TCP_SYN

class ECNChain(Chain):

    def new_flow(self, rec, ip): # pylint: disable=unused-argument
        for d in ['fwd', 'rev']:
            for t in ['syn', 'data']:
                for f in ['ect0', 'ect1', 'ce']:
                    rec['ecn_{}_{}_{}'.format(f, t, d)] = False

        return True

    def tcp(self, rec, ip, rev):
        ECT_ZERO = 0x02
        ECT_ONE = 0x01
        ECT_CE = 0x03

        ipmark = None

        if ip.traffic_class & ECT_CE == ECT_ZERO:
            ipmark = 'ecn_ect0'
        if ip.traffic_class & ECT_CE == ECT_ONE:
            ipmark = 'ecn_ect1'
        if ip.traffic_class & ECT_CE == ECT_CE:
            ipmark = 'ecn_ce'

        if ipmark is not None:
            if ip.tcp and ip.tcp.flags & TCP_SYN == TCP_SYN:
                t = 'syn'
            else:
                t = 'data'
            d = 'rev' if rev else 'fwd'
            rec['{}_{}_{}'.format(ipmark, t, d)] = True

        return True
