
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.udp import UDPChain

class TestUDPChain(ChainTestCase):

    def test_chain_udp_zerochecksum(self):
        test_trace = "udp_zerochecksum.pcap"
        self.create_observer(test_trace, [UDPChain])

        expected_mss = {
            'udp_zero_checksum_fwd': True,
            'udp_zero_checksum_rev': True
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_mss:
            assert flows[0][key] == expected_mss[key]

    def test_chain_udp_nonzerochecksum(self):
        test_trace = "udp_nonzerochecksum.pcap"
        self.create_observer(test_trace, [UDPChain])

        expected_mss = {
            'udp_zero_checksum_fwd': False,
            'udp_zero_checksum_rev': False
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_mss:
            assert flows[0][key] == expected_mss[key]
