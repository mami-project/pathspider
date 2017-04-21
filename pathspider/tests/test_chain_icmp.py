
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.icmp import ICMPChain

class TestICMPChain(ChainTestCase):

    # TODO: Need to have single flow PCAP tests for this chain.
    #
    # 1. No unreachable ICMP
    # 2. Only unreachable ICMP
    # 3. Reply followed by unreachable
    # 4. Something with IPv6
    # 5. Other ICMP messages that shouldn't be unreachable
    # 6. An ICMP unreachable message with no payload
    #
    # TODO: Drop the BasicChain from these tests once we have these flows.

    def test_icmp_single_unreachable(self):
        test_trace = "icmp_single_unreachable.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1
    
        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]


    def test_icmp_single_unreachable_nopayload(self):
        test_trace = "icmp_single_unreachable_nopayload.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1
    
        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]

#    def test_icmp_ipv6_unreachable(self):
#        test_trace = "icmp_ipv6_unreachable.pcap"
#        self.create_observer(test_trace, [ICMPChain])
#
#        expected_icmp = {
#            'icmp_unreachable': True,
#        }
#
#        flows = self.run_observer()
#        assert len(flows) == 1
#
#        for key in expected_icmp:
#            assert flows[0][key] == expected_icmp[key]


    def test_icmp_ttl_exceeded(self):
        test_trace = "icmp_ttl_exceeded.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]

    def test_icmp_synack_unreachable(self):
        test_trace = "icmp_synack_unreachable.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]


