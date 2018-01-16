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
