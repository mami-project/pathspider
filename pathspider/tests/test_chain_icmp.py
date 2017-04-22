
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.icmp import ICMPChain

class TestICMPChain(ChainTestCase):

    def test_chain_icmp_single_unreachable(self):
        # Note that this will register as in the FORWARD direction
        test_trace = "icmp_single_unreachable.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1
    
        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]


    def test_chain_icmp_single_unreachable_nopayload(self):
        # Note that this will register as in the FORWARD direction
        test_trace = "icmp_single_unreachable_nopayload.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1
    
        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]

    def test_chain_icmp_ipv6_unreachable(self):
        test_trace = "icmp_ipv6_unreachable.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]

    def test_chain_icmp_ttl_exceeded(self):
        test_trace = "icmp_ttl_exceeded.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]

    def test_chain_icmp_synack_unreachable(self):
        test_trace = "icmp_synack_unreachable.pcap"
        self.create_observer(test_trace, [ICMPChain])

        expected_icmp = {
            'icmp_unreachable': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_icmp:
            assert flows[0][key] == expected_icmp[key]
