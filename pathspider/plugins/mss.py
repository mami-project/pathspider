import heapq

import pathspider
from pathspider.base import PluggableSpider
from pathspider.single import SingleSpider
from pathspider.helpers.http import connect_http
from pathspider.helpers.http import connect_https
from pathspider.helpers.tcp import connect_tcp
from pathspider.chains.basic import BasicChain
from pathspider.chains.mss import MSSChain
from pathspider.chains.tcp import TCPChain

class MSS(SingleSpider, PluggableSpider):

    name = "mss"
    description = "TCP Maximum Segment Size"
    version = pathspider.base.__version__
    chains = [BasicChain, TCPChain, MSSChain]
    connect_supported = ["tcp", "http", "https", "dnstcp"]

    def combine_flows(self, flows):
        conditions = []

        if not flows[0]['observed']:
            return ['pathspider.not_observed']

        conditions.append(self.combine_connectivity(flows[0]['tcp_connected']))

        if flows[0]['tcp_connected']:
            conditions.append('mss.option.local.value:' + str(flows[0]['mss_value_fwd']))
            if flows[0]['mss_len_rev'] is not None:
                conditions.append('mss.option.remote.value:' + str(flows[0]['mss_value_rev']))
                if (flows[0]['mss_value_rev'] < flows[0]['mss_value_fwd']):
                    conditions.append('mss.option.received.deflated')
                elif (flows[0]['mss_value_rev'] == flows[0]['mss_value_fwd']):
                    conditions.append('mss.option.received.unchanged')
                else:
                    conditions.append('mss.option.received.inflated')
            else:
                conditions.append('mss.option.received.absent')

        return conditions

    @classmethod
    def aggregate(self, result_feeder):
        online = 0
        offline = 0
        absent = 0
        msss6 = {}
        msss4 = {}
        top500_v4 = []
        bottom500_v4 = []
        top500_v6 = []
        bottom500_v6 = []
        absr = []

        class MSSResult:
            def __init__(self, mss, result, reverse=False):
                self.mss = mss
                self.result = result
                self.reverse = reverse

            def __lt__(self, other):
                return self.mss > other.mss if self.reverse else self.mss < other.mss

            def __gt__(self, other):
                return self.mss < other.mss if self.reverse else self.mss > other.mss
 
        for result in result_feeder():
            if 'mss.connectivity.offline' in result['conditions']:
                offline += 1
                continue
            online += 1
            if 'mss.option.received.absent' in result['conditions']:
                absent += 1
                absr.append(result)
                continue
            for condition in result['conditions']:
                if condition.startswith('mss.option.remote.value:'):
                    mss = int(condition.split(':')[1])
                    if '.' in result['dip']:
                        if mss not in msss4:
                            msss4[mss] = 0
                        msss4[mss] += 1
                        if len(top500_v4) < 500 or mss > top500_v4[0].mss:
                            if len(top500_v4) == 500:
                                heapq.heappop(top500_v4)
                            heapq.heappush(top500_v4, MSSResult(mss, result))
                        if len(bottom500_v4) < 500 or mss < bottom500_v4[0].mss:
                            if len(bottom500_v4) == 500:
                                heapq.heappop(bottom500_v4)
                            heapq.heappush(bottom500_v4, MSSResult(mss, result, reverse=True))

                    if ':' in result['dip']:
                        if mss not in msss6:
                            msss6[mss] = 0
                        msss6[mss] += 1
                        if len(top500_v6) < 500 or mss > top500_v6[0].mss:
                            if len(top500_v6) == 500:
                                heapq.heappop(top500_v6)
                            heapq.heappush(top500_v6, MSSResult(mss, result))
                        if len(bottom500_v6) < 500 or mss < bottom500_v6[0].mss:
                            if len(bottom500_v6) == 500:
                                heapq.heappop(bottom500_v6)
                            heapq.heappush(bottom500_v6, MSSResult(mss, result, reverse=True))
        return {
                'online': online,
                'offline': offline,
                'absent': absent,
                'msss4': msss4,
                'msss6': msss6,
                'top500_v4': [x.mss for x in top500_v4],
                'bottom500_v4': [x.mss for x in bottom500_v4],
                'top500_v6': [x.mss for x in top500_v6],
                'bottom500_v6': [x.mss for x in bottom500_v6],
                'absr': absr
               }
