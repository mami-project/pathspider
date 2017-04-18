
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.dscp import DSCPChain

class TestDSCPChain(ChainTestCase):

    def test_observer_dscp_tcp_allzero(self):
        test_trace = "dscp_tcp_allzero.pcap"
        self.create_observer(test_trace, [DSCPChain])

        expected_dscp = {
            'dscp_mark_syn_fwd': 0,
            'dscp_mark_syn_rev': 0,
            'dscp_mark_data_fwd': 0,
            'dscp_mark_data_rev': 0,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_dscp:
            assert flows[0][key] == expected_dscp[key]

    def test_observer_dscp_tcp_fwd3(self):
        test_trace = "dscp_tcp_fwd3.pcap"
        self.create_observer(test_trace, [DSCPChain])

        expected_dscp = {
            'dscp_mark_syn_fwd': 3,
            'dscp_mark_syn_rev': 0,
            'dscp_mark_data_fwd': 3,
            'dscp_mark_data_rev': 0,
        }

        flows = self.run_observer()

        assert len(flows) == 1

        for key in expected_dscp:
            assert flows[0][key] == expected_dscp[key]

    def test_observer_dscp_ipv6_tcp_fwd3(self):
        test_trace = "dscp_ipv6_tcp_fwd3.pcap"
        self.create_observer(test_trace, [DSCPChain])

        expected_dscp = {
            'dscp_mark_syn_fwd': 3,
            'dscp_mark_syn_rev': 0,
            'dscp_mark_data_fwd': 3,
            'dscp_mark_data_rev': 0,
        }

        flows = self.run_observer()

        assert len(flows) == 1

        for key in expected_dscp:
            assert flows[0][key] == expected_dscp[key]

    def test_observer_dscp_udp_allzero(self):
        test_trace = "dscp_udp_allzero.pcap"
        self.create_observer(test_trace, [DSCPChain])

        expected_dscp = {
            'dscp_mark_syn_fwd': None,
            'dscp_mark_syn_rev': None,
            'dscp_mark_data_fwd': 0,
            'dscp_mark_data_rev': 0,
        }

        flows = self.run_observer()

        assert len(flows) == 1

        for key in expected_dscp:
            assert flows[0][key] == expected_dscp[key]

    def test_observer_dscp_udp_fwd3(self):
        test_trace = "dscp_udp_fwd3.pcap"
        self.create_observer(test_trace, [DSCPChain])

        expected_dscp = {
            'dscp_mark_syn_fwd': None,
            'dscp_mark_syn_rev': None,
            'dscp_mark_data_fwd': 3,
            'dscp_mark_data_rev': 0,
        }

        flows = self.run_observer()

        assert len(flows) == 1

        for key in expected_dscp:
            assert flows[0][key] == expected_dscp[key]
