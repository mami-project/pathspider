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

    def config_no_dscp(self):  # pylint: disable=no-self-use
        """
        Disables DSCP marking via iptables.
        """

        logger = logging.getLogger('dscp')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-F'])
        logger.debug("Configurator disabled DSCP marking")

    def config_dscp(self):
        """
        Enables DSCP marking via iptables.
        """
        logger = logging.getLogger('dscp')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([
                iptables, '-t', 'mangle', '-A', 'OUTPUT', '-j', 'DSCP',
                '--set-dscp', str(self.args.codepoint)
            ])
        logger.debug("Configurator enabled DSCP marking")

    configurations = [config_no_dscp, config_dscp]

    def combine_flows(self, flows):
        conditions = []

        # discard non-observed flows
        for f in flows:
            if not f['observed']:
                return ['pathspider.not_observed']

        baseline = 'dscp.' + str(flows[0]['dscp_mark_syn_fwd'] or
                                 flows[0]['dscp_mark_data_fwd']) + '.'
        test = 'dscp.' + str(flows[1]['dscp_mark_syn_fwd'] or
                             flows[1]['dscp_mark_data_fwd']) + '.'

        if flows[0]['spdr_state'] == CONN_OK and flows[1][
                'spdr_state'] == CONN_OK:
            cond_conn = test + 'connectivity.works'
        elif flows[0]['spdr_state'] == CONN_OK and not flows[1][
                'spdr_state'] == CONN_OK:
            cond_conn = test + 'connectivity.broken'
        elif not flows[0]['spdr_state'] == CONN_OK and flows[1][
                'spdr_state'] == CONN_OK:
            cond_conn = test + 'connectivity.transient'
        else:
            cond_conn = test + 'connectivity.offline'
        conditions.append(cond_conn)

        conditions.append(baseline + 'replymark:' + str(
            flows[1]['dscp_mark_syn_rev'] or flows[1]['dscp_mark_data_rev']))
        conditions.append(test + 'replymark:' + str(
            flows[0]['dscp_mark_syn_rev'] or flows[0]['dscp_mark_data_rev']))

        return conditions

    @staticmethod
    def extra_args(parser):
        parser.add_argument(
            "--codepoint",
            type=int,
            choices=range(0, 64),
            default='48',
            metavar="[0-63]",
            help="DSCP codepoint to send (Default: 48)")
