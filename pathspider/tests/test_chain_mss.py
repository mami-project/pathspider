
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.mss import MSSChain

class TestMSSChain(ChainTestCase):

    def test_chain_mss_ipv4(self):
        test_trace = "mss_ipv4.pcap"
        self.create_observer(test_trace, [MSSChain])

        expected_mss = {
            'mss_len_fwd': 4,
            'mss_len_rev': 4,
            'mss_value_fwd': 1460,
            'mss_value_rev': 1452
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_mss:
            assert flows[0][key] == expected_mss[key]

    def test_chain_mss_ipv6(self):
        test_trace = "mss_ipv6.pcap"
        self.create_observer(test_trace, [MSSChain])

        expected_mss = {
            'mss_len_fwd': 4,
            'mss_len_rev': 4,
            'mss_value_fwd': 1440,
            'mss_value_rev': 1360
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_mss:
            assert flows[0][key] == expected_mss[key]

    def test_chain_mss_none(self):
        test_trace = "mss_none.pcap"
        self.create_observer(test_trace, [MSSChain])

        expected_mss = {
            'mss_len_fwd': None,
            'mss_len_rev': None,
            'mss_value_fwd': None,
            'mss_value_rev': None
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_mss:
            assert flows[0][key] == expected_mss[key]

    def test_chain_mss_3bytes(self):
        test_trace = "mss_3bytes.pcap"
        self.create_observer(test_trace, [MSSChain])

        expected_mss = {
            'mss_len_fwd': 5,
            'mss_len_rev': None,
            'mss_value_fwd': 1460,
            'mss_value_rev': None
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_mss:
            assert flows[0][key] == expected_mss[key]
