
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.basic import BasicChain

class TestBasicChain(ChainTestCase):

    # TODO: Add tests for UDP/SCTP/UDP-lite/DCCP

    def test_chain_basic_ipv4_tcp(self):
        test_trace = "basic_ipv4_tcp.pcap"
        self.create_observer(test_trace, [BasicChain])

        expected_basic = {
            'oct_fwd': 1747,
            'dp': 80,
            'pkt_rev': 32,
            'pkt_fwd': 32,
            'proto': 6,
            'oct_rev': 41030,
            'sip': '139.133.208.62',
            'sp': 38878,
            'dip': '139.133.1.4'
        }

        flows = self.run_observer()
        print(flows)
        assert len(flows) == 1

        for key in expected_basic:
            assert flows[0][key] == expected_basic[key]

    def test_chain_basic_ipv6_tcp(self):
        test_trace = "basic_ipv6_tcp.pcap"
        self.create_observer(test_trace, [BasicChain])

        expected_basic = {
            'oct_fwd': 514,
            'dp': 80,
            'pkt_rev': 4,
            'pkt_fwd': 6,
            'proto': 6,
            'oct_rev': 799,
            'sip': '2001:630:241:20f:c2ea:e939:f310:9c32',
            'sp': 39956,
            'dip': '2a00:1450:4009:810::200e',
        }

        flows = self.run_observer()
        print(flows)
        assert len(flows) == 1

        for key in expected_basic:
            assert flows[0][key] == expected_basic[key]

    def test_chain_basic_ipv4_udp(self):
        test_trace = "basic_ipv4_udp.pcap"
        self.create_observer(test_trace, [BasicChain])

        expected_basic = {
            'oct_fwd': 56,
            'dp': 53,
            'pkt_rev': 1,
            'pkt_fwd': 1,
            'proto': 17,
            'oct_rev': 267,
            'sip': '172.22.152.138',
            'sp': 57606,
            'dip': '8.8.8.8'
        }

        flows = self.run_observer()
        print(flows)
        assert len(flows) == 1

        for key in expected_basic:
            assert flows[0][key] == expected_basic[key]

    def test_chain_basic_ipv6_udp(self):
        test_trace = "basic_ipv6_udp.pcap"
        self.create_observer(test_trace, [BasicChain])

        expected_basic = {
            'oct_fwd': 76,
            'dp': 53,
            'pkt_rev': 1,
            'pkt_fwd': 1,
            'proto': 17,
            'oct_rev': 287,
            'sip': '2001:470:1d58:1337:4100:e1a1:8dcf:488',
            'sp': 40672,
            'dip': '2001:4860:4860::8888',
        }

        flows = self.run_observer()
        print(flows)
        assert len(flows) == 1

        for key in expected_basic:
            assert flows[0][key] == expected_basic[key]

    def test_chain_basic_ipv4_non_udp_tcp(self):
        test_trace = "basic_ipv4_non_udp_tcp.pcap"
        self.create_observer(test_trace, [BasicChain])

        expected_basic = {
            'oct_fwd': 506,
            'dp': None,
            'pkt_rev': 0,
            'pkt_fwd': 11,
            'proto': 112,
            'oct_rev': 0,
            'sip': '192.168.0.10',
            'sp': None,
            'dip': '224.0.0.18'
        }

        flows = self.run_observer()
        print(flows)
        assert len(flows) == 1

        for key in expected_basic:
            assert flows[0][key] == expected_basic[key]
