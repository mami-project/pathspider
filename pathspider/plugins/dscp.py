import logging
import subprocess

import pathspider.base
from pathspider.base import CONN_OK
from pathspider.base import PluggableSpider
from pathspider.sync import SynchronizedSpider
from pathspider.chains.basic import BasicChain
from pathspider.chains.tcp import TCPChain
from pathspider.chains.dscp import DSCPChain
from pathspider.chains.dns import DNSChain

class DSCP(SynchronizedSpider, PluggableSpider):

    name = "dscp"
    description = "Differentiated Services Codepoints"
    version = pathspider.base.__version__
    chains = [BasicChain, DSCPChain, TCPChain, DNSChain]
    connect_supported = ["http", "tcp", "dnstcp", "dnsudp"]

    def generate_f(self, i):
        def config_dscp(self):
            logger = logging.getLogger('dscp')
            for iptables in ['iptables', 'ip6tables']:
                subprocess.check_call([
                    iptables, '-t', 'mangle', '-A', 'OUTPUT', '-j', 'DSCP',
                    '--set-dscp', str(i)
                ])
            logger.debug("Configurator enabled DSCP marking")
        return config_dscp 
     
    def configurations(self):
        def config_no_dscp(self):  # pylint: disable=no-self-use
           """
           Disables DSCP marking via iptables
           """
    
           logger = logging.getLogger('dscp')
           for iptables in ['iptables', 'ip6tables']:
               subprocess.check_call([iptables, '-t', 'mangle', '-F'])
           logger.debug("Configurator disabled DSCP marking")

        a = [config_no_dscp]
        for arg in self.args.codepoint:
            a.append(self.generate_f(arg))
        return a
    
    def combine_flows(self, flows):
        # discard non-observed flows
        total_flows = len(flows)
        for f in flows:
            if not f['observed']:
                return ['pathspider.not_observed']

        conditions = []

        baseline = 'dscp.' + str(flows[0]['dscp_mark_syn_fwd'] or
                                 flows[0]['dscp_mark_data_fwd'])
        baseline_replymark = flows[0]['dscp_mark_syn_rev'] or flows[0]['dscp_mark_data_rev']

        if baseline_replymark is not None:
            conditions.append(baseline + '.replymark:' + str(baseline_replymark))

        for i in range(1, total_flows):
            test = 'dscp.' + str(flows[i]['dscp_mark_syn_fwd'] or
                                 flows[i]['dscp_mark_data_fwd'])
            conditions.append(self.combine_connectivity(
                                  flows[0]['spdr_state'] == CONN_OK,
                                  experimental = flows[i]['spdr_state'] == CONN_OK,
                                  prefix = test)
                             )
            test_replymark = flows[i]['dscp_mark_syn_rev'] or flows[i]['dscp_mark_data_rev']
            if test_replymark is not None:
                 conditions.append(test + '.replymark:' + str(test_replymark))

        return conditions

    @staticmethod
    def extra_args(parser):
        parser.add_argument(
            "--codepoint",
            type=int,
            choices=range(0, 64),
            default=['48'],
            nargs='*',
            metavar="[0-63]",
            help="DSCP codepoint to send (Default: 48)")
