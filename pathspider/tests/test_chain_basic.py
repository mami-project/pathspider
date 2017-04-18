
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.basic import BasicChain

class TestBasicChain(ChainTestCase):



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
