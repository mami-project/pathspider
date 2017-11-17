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
        ect1success = "False"
        ect0success = "False"
        cesuccess = "False"
        ect0 = 0
        ect1 = 0
        ce = 0
        
        if flows[0]['spdr_state'] == CONN_OK & flows[1]['spdr_state'] == CONN_OK & flows[2]['spdr_state'] == CONN_OK & flows[3]['spdr_state'] == CONN_OK & flows[4]['spdr_state'] == CONN_OK :
            conditions.append("ecn.connectivity.ce.works")
        elif flows[0]['spdr_state'] == CONN_OK & flows[1]['spdr_state'] == CONN_OK & flows[2]['spdr_state'] == CONN_OK & flows[3]['spdr_state'] == CONN_OK & flows[4]['spdr_state'] != CONN_OK :
            conditions.append("ecn.connectivity.ect.works")
        elif flows[0]['spdr_state'] == CONN_OK & flows[1]['spdr_state'] != CONN_OK & flows[2]['spdr_state'] != CONN_OK & flows[3]['spdr_state'] != CONN_OK & flows[4]['spdr_state'] != CONN_OK :
            conditions.append("ecn.connectivity.works")
        elif flows[0]['spdr_state'] != CONN_OK & flows[1]['spdr_state'] != CONN_OK & flows[2]['spdr_state'] != CONN_OK & flows[3]['spdr_state'] != CONN_OK & flows[4]['spdr_state'] != CONN_OK :
            conditions.append("ecn.connectivity.offline")
        else:
            conditions.append("ecn.connectivity.transient")

        #for i in range(0,len(flows)):
        #if flows[i]['observed'] and flows[i]['tcp_connected']:    
        try:
            if (flows[1]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE) &(flows[2]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE) &(flows[3]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE) & (flows[4]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE):
                conditions.append("ecn.negotiation.ce.suceeded")
            
            elif (flows[1]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE) &(flows[2]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE) &(flows[3]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE) & (flows[4]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE):
                conditions.append("ecn.negotiation.ect.suceeded")
            
            elif (flows[1]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE) &(flows[2]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE) &(flows[3]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE) & (flows[4]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE):
                conditions.append("ecn.negotiation.suceeded")
                
            elif (flows[1]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE) &(flows[2]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE) &(flows[3]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE) & (flows[4]['tcp_synflags_rev'] & TCP_SAEC != TCP_SAE):
                conditions.append("ecn.negotiation.failed")
            
            else:
                conditions.append("ecn.negotiation.transient")
        
        except KeyError:
            conditions.append("Not all flags observed")    
#             if flows[i]['spdr_state'] == CONN_OK:
#                 work += 1
#             if flows[i]['observed'] and flows[i]['tcp_connected']:
#                 try:
#                     
#                     if flows[i]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE:
#                         success += 1
#                 except TypeError:
#                     print("Type error in flow i %u"%i)
#             
#             try:        
#                 if flows[i]['ecn_ect1_syn_rev']:
#                     ect1 += 1
#                 if flows[i]['ecn_ect0_syn_rev']:
#                     ect0 += 1
#                 if flows[i]['ecn_ce_syn_rev']:
#                     ce += 1
#             except KeyError:
#             
#                 print("Key error in ecn_syn_rev: %s"%str(flows[i]['dip']))
#             
#         try:       
#             if flows[2]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE:
#                 ect0success = "True"
#         except TypeError:
#             print("Type error in flow 2 %s"%str(flows[2]['tcp_synflags_rev']))
#             ect0success = "FAILFAIL1"
#         except KeyError:
#             print("Key error in flow 2")
#             ect0success = "FAILFAIL2"
#         try:
#             if flows[3]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE:
#                 ect1success = "True"
#         except TypeError:
#             print("Type error in flow 3 %s"%str(flows[3]['tcp_synflags_rev']))
#             ect1success = "FAILFAIL1"
#         except KeyError:
#             print("Key error in flow 3")
#             ect1success = "FAILFAIL2"
#         try:
#             if flows[4]['tcp_synflags_rev'] & TCP_SAEC == TCP_SAE:
#                 cesuccess = "True"
#         except TypeError:
#             print("Type error in flow 4 %s"%str(flows[4]['tcp_synflags_rev']))
#             cesuccess = "FAILFAIL1"
#         except KeyError:
#             print("Key error in flow 4")
#             ect1success = "FAILFAIL2"   
#                     
# 
#                 
#         conditions.append('ecn.connectivity.works %s/%s' %(work,len(flows)-1))
#         conditions.append('ecn.negotiation.succeeded %s/%s' %(success,len(flows)-1) )
#         conditions.append('ecn.ect0.success %s' %(ect0success))
#         conditions.append('ecn.ect1.success %s' %(ect1success))
#         conditions.append('ecn.ce.success %s' %(cesuccess))
#         conditions.append('ecn.ect0.rev.seen %s/%s' %(ect0,len(flows)-1) )
#         conditions.append('ecn.ect1.rev.seen %s/%s' %(ect1,len(flows)-1) )
#         conditions.append('ecn.ce.rev.seen %s/%s' %(ce,len(flows)-1) )



        return conditions
    
    def packet_modifier(self):
        
        return 
