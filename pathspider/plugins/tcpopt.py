import logging
import subprocess

import pathspider.base
from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.sync import SynchronizedSpider
from pathspider.chains.basic import BasicChain
from pathspider.chains.tcp import TCPChain


class ECN(SynchronizedSpider, PluggableSpider):

    name = "tcpopt"
    description = "TCP Options (Timestamp, Windows Scaling, SACK)"
    version = pathspider.base.__version__
    chains = [BasicChain, TCPChain, TCPOptChain]
    connect_supported = ["http", "https", "tcp", "dnstcp"]

    def config_no_opt(self): # pylint: disable=no-self-use
        """
        Disables TCP Options via sysctl.
        """

        logger = logging.getLogger('tcpopt')
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_timestamps=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_window_scaling=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_sack=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        logger.debug("Configurator disabled TCP Options")

    def config_ws(self): # pylint: disable=no-self-use
        """
        Enable only TSOpt via sysctl.
        """

        logger = logging.getLogger('tcpopt')
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_timestamps=1'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_window_scaling=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_sack=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled TSOpt")

    def config_ws(self): # pylint: disable=no-self-use
        """
        Enable only WSOpt via sysctl.
        """

        logger = logging.getLogger('tcpopt')
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_timestamps=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_window_scaling=1'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_sack=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled WSOpt")

    def config_sack(self): # pylint: disable=no-self-use
        """
        Enable only SACK via sysctl.
        """

        logger = logging.getLogger('tcpopt')
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_timestamps=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_window_scaling=0'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_sack=1'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled SACK")

    configurations = [config_no_opt, config_ts, config_ws, config_sack]

    def combine_flows(self, flows):
        conditions = []

        conditions.append(self.combine_connectivity(
                                             flows[0]['spdr_state'] == CONN_OK,
                                             flows[1]['spdr_state'] == CONN_OK, 'tsopt'))
        conditions.append(self.combine_connectivity(
                                             flows[0]['spdr_state'] == CONN_OK,
                                             flows[2]['spdr_state'] == CONN_OK, 'wsopt'))
        conditions.append(self.combine_connectivity(
                                             flows[0]['spdr_state'] == CONN_OK,
                                             flows[3]['spdr_state'] == CONN_OK, 'sack'))

        for f in flows:
            if not f['observed']:
                conditions.append('pathspider.not_observed')
                break

        if flows[1]['observed'] and flows[1]['tcp_connected']:
            if flows[1]['tcpopt_ts']:
                conditions.append('tsopt.negotiation.succeeded')
            else:
                conditions.append('tsopt.negotiation.failed')
        if flows[2]['observed'] and flows[2]['tcp_connected']:
            if flows[2]['tcpopt_ws']:
                conditions.append('wsopt.negotiation.succeeded')
            else:
                conditions.append('wsopt.negotiation.failed')
        if flows[3]['observed'] and flows[3]['tcp_connected']:
            if flows[3]['tcpopt_sack']:
                conditions.append('sack.negotiation.succeeded')
            else:
                conditions.append('sack.negotiation.failed')

        if flows[0]['observed'] and flows[0]['tcp_connected']:
            if flows[0]['tcpopt_ts']:
                conditions.append('tsopt.sendwithoutrequest.true')
            else:
                conditions.append('tsopt.sendwithoutrequest.false')
            if flows[0]['tcpopt_ws']:
                conditions.append('wsopt.sendwithoutrequest.true')
            else:
                conditions.append('tsopt.sendwithoutrequest.false')
            if flows[0]['tcpopt_sack']:
                conditions.append('sack.sendwithoutrequest.true')
            else:
                conditions.append('sack.sendwithoutrequest.false')

        return conditions
