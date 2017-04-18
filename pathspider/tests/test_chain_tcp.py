
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.tcp import TCPChain
from pathspider.chains.tcp import TCP_SYN
from pathspider.chains.tcp import TCP_ACK
from pathspider.chains.tcp import TCP_ECE
from pathspider.chains.tcp import TCP_CWR

class TestTCPChain(ChainTestCase):

    def test_chain_tcp_ipv4_simple(self):
        test_trace = "tcp_ipv4_simple.pcap"
        self.create_observer(test_trace, [TCPChain])

        expected_tcp = {
            'tcp_synflags_fwd': TCP_SYN,
            'tcp_synflags_rev': TCP_SYN | TCP_ACK,
            'tcp_connected': True,
            'tcp_fin_fwd': True,
            'tcp_fin_rev': True,
            'tcp_rst_fwd': False,
            'tcp_rst_rev': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_tcp:
            assert flows[0][key] == expected_tcp[key]

    def test_chain_tcp_ipv6_simple(self):
        test_trace = "tcp_ipv6_simple.pcap"
        self.create_observer(test_trace, [TCPChain])

        expected_tcp = {
            'tcp_synflags_fwd': TCP_SYN,
            'tcp_synflags_rev': TCP_SYN | TCP_ACK,
            'tcp_connected': True,
            'tcp_fin_fwd': True,
            'tcp_fin_rev': True,
            'tcp_rst_fwd': False,
            'tcp_rst_rev': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_tcp:
            assert flows[0][key] == expected_tcp[key]

    def test_chain_tcp_ipv4_ecn(self):
        test_trace = "tcp_ipv4_ecn.pcap"
        self.create_observer(test_trace, [TCPChain])

        expected_tcp = {
            'tcp_synflags_fwd': TCP_SYN | TCP_ECE | TCP_CWR,
            'tcp_synflags_rev': TCP_SYN | TCP_ACK | TCP_ECE,
            'tcp_connected': True,
            'tcp_fin_fwd': True,
            'tcp_fin_rev': True,
            'tcp_rst_fwd': False,
            'tcp_rst_rev': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_tcp:
            assert flows[0][key] == expected_tcp[key]

    def test_chain_tcp_ipv6_ecn(self):
        test_trace = "tcp_ipv6_ecn.pcap"
        self.create_observer(test_trace, [TCPChain])

        expected_tcp = {
            'tcp_synflags_fwd': TCP_SYN | TCP_ECE | TCP_CWR,
            'tcp_synflags_rev': TCP_SYN | TCP_ACK | TCP_ECE,
            'tcp_connected': True,
            'tcp_fin_fwd': True,
            'tcp_fin_rev': True,
            'tcp_rst_fwd': False,
            'tcp_rst_rev': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_tcp:
            assert flows[0][key] == expected_tcp[key]

    def test_chain_tcp_ipv4_rst(self):
        test_trace = "tcp_ipv4_rst.pcap"
        self.create_observer(test_trace, [TCPChain])

        expected_tcp = {
            'tcp_synflags_fwd': TCP_SYN,
            'tcp_synflags_rev': TCP_SYN | TCP_ACK,
            'tcp_connected': True,
            'tcp_fin_fwd': False,
            'tcp_fin_rev': False,
            'tcp_rst_fwd': False,
            'tcp_rst_rev': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_tcp:
            assert flows[0][key] == expected_tcp[key]
