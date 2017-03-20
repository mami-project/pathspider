import logging
import subprocess

import pathspider.base
from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.sync import SynchronizedSpider
from pathspider.chains.basic import BasicChain
from pathspider.chains.tcp import TCPChain
from pathspider.chains.tcp import TCP_SAE
from pathspider.chains.tcp import TCP_SAEC
from pathspider.chains.ecn import ECNChain


class ECN(SynchronizedSpider, PluggableSpider):

    name = "ecn"
    description = "Explicit Congestion Notification"
    version = pathspider.base.__version__
    chains = [BasicChain, TCPChain, ECNChain]
    connect_supported = ["http", "https", "tcp", "dnstcp"]

    def config_no_ecn(self): # pylint: disable=no-self-use
        """
        Disables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        logger.debug("Configurator disabled ECN")

    def config_ecn(self): # pylint: disable=no-self-use
        """
        Enables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled ECN")

    configurations = [config_no_ecn, config_ecn]

    def combine_flows(self, flows):
        conditions = []

        if flows[0]['spdr_state'] == CONN_OK and flows[1][
                'spdr_state'] == CONN_OK:
            conditions.append('ecn.connectivity.works')
        elif flows[0]['spdr_state'] == CONN_OK and not flows[1][
                'spdr_state'] == CONN_OK:
            conditions.append('ecn.connectivity.broken')
        elif not flows[0]['spdr_state'] == CONN_OK and flows[1][
                'spdr_state'] == CONN_OK:
            conditions.append('ecn.connectivity.transient')
        else:
            conditions.append('ecn.connectivity.offline')

        if flows[1]['observed'] and flows[1]['tcp_connected']:
            if flows[1]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE:
                conditions.append('ecn.negotiation.succeeded')
            elif flows[1]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAEC:
                conditions.append('ecn.negotiation.reflected')
            else:
                conditions.append('ecn.negotiation.failed')

            conditions.append('ecn.ipmark.ect0.seen' if (
                flows[1]['ecn_ect0_syn_rev'] or flows[1]['ecn_ect0_data_rev'])
                              else 'ecn.ipmark.ect0.not_seen')
            conditions.append('ecn.ipmark.ect1.seen' if (
                flows[1]['ecn_ect1_syn_rev'] or flows[1]['ecn_ect1_data_rev'])
                              else 'ecn.ipmark.ect1.not_seen')
            conditions.append('ecn.ipmark.ce.seen' if (
                flows[1]['ecn_ce_syn_rev'] or flows[1]['ecn_ce_data_rev']) else
                              'ecn.ipmark.ce.not_seen')

        return conditions
