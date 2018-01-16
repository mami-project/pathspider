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

        if flows[0]['tcp_connected']:
            conditions.append('mss.connectivity.online')
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
        else:
            conditions.append('mss.connectivity.offline')

        return conditions

    @classmethod
    def aggregate(self, result_feeder):
        online = 0
        offline = 0
        absent = 0
        msss = {}
        top100 = []
        bot100 = []
        abs100 = []

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
                abs100.append(result)
                continue
            for condition in result['conditions']:
                if condition.startswith('mss.option.received.value:'):
                    mss = int(condition.split(':')[1])
                    if mss not in msss:
                        msss[mss] = 0
                    msss[mss] += 1
                    if len(top100) < 100 or mss > top100[0].mss:
                        if len(top100) == 100: heapq.heappop(top100)
                        heapq.heappush(top100, MSSResult(mss, result))
                    if len(bot100) < 100 or mss < bot100[0].mss:
                        if len(bot100) == 100: heapq.heappop(bot100)
                        heapq.heappush(bot100, MSSResult(mss, result, reverse=True))
        return {
                'online': online,
                'offline': offline,
                'absent': absent,
                'msss': msss,
                'top100': [x.result for x in top100],
                'bottom100': [x.result for x in bot100],
                'absent100': abs100
               }
