
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.basic import BasicChain
from pathspider.chains.icmp import ICMPChain

class TestICMPChain(ChainTestCase):

    # TODO: Need to have single flow PCAP tests for this chain.
    #
    # 1. No unreachable ICMP
    # 2. Only unreachable ICMP
    # 3. Reply followed by unreachable
    # 4. Something with IPv6
    # 5. Other ICMP messages that shouldn't be unreachable
    #
    # TODO: Drop the BasicChain from these tests once we have these flows.

    def test_icmpchain_unreachable_presence(self):
        test_trace = "icmp_unreachable.pcap"
        self.create_observer(test_trace, [BasicChain, ICMPChain])
        flows = self.run_observer()
    
        unreachables = [
            '172.20.152.190',
            ]
    
        for f in flows:
            assert f['icmp_unreachable'] == (f['dip'] in unreachables)
