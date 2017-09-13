import logging
import subprocess

import pathspider.base
from pathspider.base import PluggableSpider
from pathspider.base import CONN_OK
from pathspider.sync import SynchronizedSpider
from pathspider.chains.basic import BasicChain
from pathspider.traceroute_base import traceroute
from pathspider.chains.tcp import TCPChain
from pathspider.chains.tcp import TCP_SAE
from pathspider.chains.tcp import TCP_SAEC
from pathspider.chains.ecn import ECNChain
from pathspider.chains.traceroute import tracerouteChain
from pathspider.chains.dscp import DSCPChain

class ECNFLAGS(SynchronizedSpider, PluggableSpider, traceroute):

    name = "ecnflags"
    description = "Explicit Congestion Notification"
    version = pathspider.base.__version__
    chains = [BasicChain, TCPChain, ECNChain, tracerouteChain, DSCPChain]
    connect_supported = ["http", "https", "tcp", "dnstcp"]
    traceroute_conditions = ["ecn.connectivity.works", "ecn.connectivity.broken"]

    def config_no_ecn(self): # pylint: disable=no-self-use
        """
        Disables ECN negotiation via sysctl.
        """

        logger = logging.getLogger('ecn')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-F'])
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
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-F'])
        subprocess.check_call(
            ['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        logger.debug("Configurator enabled ECN")
        
    def config_ecn_ect0(self):
        """
        ECN negotiation with first bit set in IP header
        """
        logger = logging.getLogger('ecn')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-A', 'OUTPUT', '-j', 'TOS', '--set-tos', '0x01/0xFF' ])
        logger.debug("Configurator set ECN IP bits to 1")
        
    def config_ecn_ect1(self):
        """
        ECN negotiation with second bit set in IP header
        """
        logger = logging.getLogger('ecn')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-A', 'OUTPUT', '-j', 'TOS', '--set-tos', '0x02/0xFF' ])
        logger.debug("Configurator set ECN IP bits to 2")
        
    def config_ecn_ce(self):
        """
        ECN negotiation with both bits set in IP header
        """
        logger = logging.getLogger('ecn')
        for iptables in ['iptables', 'ip6tables']:
            subprocess.check_call([iptables, '-t', 'mangle', '-A', 'OUTPUT', '-j', 'TOS', '--set-tos', '0x03/0xFF'])
        logger.debug("Configurator set ECN IP bits to 3")
        
    configurations = [config_no_ecn, config_ecn, config_ecn_ect0, config_ecn_ect1, config_ecn_ce]

    def combine_flows(self, flows):
        conditions = []
        
        work = 0
        success = 0
        ect1 = 0
        ect0 = 0
        ce = 0
        
        if flows[0]['spdr_state'] == CONN_OK:
            conditions.append("non-ecn.connectivity.works")
        
        for i in range(1,len(flows)):
            if flows[i]['spdr_state'] == CONN_OK:
                work += 1
            #if flows[i]['observed'] and flows[i]['tcp_connected']:
            if flows[i]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE:
                success += 1
            if flows[i]['ecn_ect1_syn_fwd']:
                ect1 += 1
            if flows[i]['ecn_ect0_syn_fwd']:
                ect0 += 1
            if flows[i]['ecn_ce_syn_fwd']:
                ce += 1
                
        conditions.append('ecn.connectivity.works %s/%s' %(work,len(flows)-1))
        conditions.append('ecn.negotiation.succeeded %s/%s' %(success,len(flows)-1) )
        conditions.append('ecn.ect0.seen %s/%s' %(ect0,len(flows)-1))
        conditions.append('ecn.ect1.seen %s/%s' %(ect1,len(flows)-1))
        conditions.append('ecn.ce.seen %s/%s' %(ce,len(flows)-1))



        return conditions
    
    def packet_modifier(self):
        
        return 
