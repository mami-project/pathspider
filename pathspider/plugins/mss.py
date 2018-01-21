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
        msss = {}
        top500 = []
        bottom500 = []
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
                if condition.startswith('mss.option.received.value:'):
                    mss = int(condition.split(':')[1])
                    if mss not in msss:
                        msss[mss] = 0
                    msss[mss] += 1
                    if len(top500) < 500 or mss > top500[0].mss:
                        if len(top500) == 500:
                            heapq.heappop(top500)
                        heapq.heappush(top500, MSSResult(mss, result))
                    if len(bottom500) < 500 or mss < bottom500[0].mss:
                        if len(bottom500) == 500:
                            heapq.heappop(bottom500)
                        heapq.heappush(bottom500, MSSResult(mss, result, reverse=True))
        return {
                'online': online,
                'offline': offline,
                'absent': absent,
                'msss': msss,
                'top500': [x.result for x in top500],
                'bottom500': [x.result for x in bottom500],
                'absr': absr
               }
