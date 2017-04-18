
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.ecn import ECNChain
from pathspider.chains.tcp import TCP_SEC
from pathspider.chains.tcp import TCP_SAE

class TestECNChain(ChainTestCase):

    def test_chain_ecn_fake_fwd_ce(self):
        test_trace = "ecn_fake_fwd_ce.pcap"
        self.create_observer(test_trace, [ECNChain])

        expected_ecn = {
            'ecn_ect0_syn_fwd': False,
            'ecn_ect1_syn_fwd': False,
            'ecn_ce_syn_fwd': True,
            'ecn_ect0_data_fwd': False,
            'ecn_ect1_data_fwd': False,
            'ecn_ce_data_fwd': True,
            'ecn_ect0_syn_rev': False,
            'ecn_ect1_syn_rev': False,
            'ecn_ce_syn_rev': False,
            'ecn_ect0_data_rev': False,
            'ecn_ect1_data_rev': False,
            'ecn_ce_data_rev': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_ecn:
            assert flows[0][key] == expected_ecn[key]

    def test_chain_ecn_ipv6_unreachable_ce_on_syn(self):
        test_trace = "ecn_ipv6_unreachable_ce_on_syn.pcap"
        self.create_observer(test_trace, [ECNChain])

        expected_ecn = {
            'ecn_ect0_syn_fwd': False,
            'ecn_ect1_syn_fwd': False,
            'ecn_ce_syn_fwd': True,
            'ecn_ect0_data_fwd': False,
            'ecn_ect1_data_fwd': False,
            'ecn_ce_data_fwd': False,
            'ecn_ect0_syn_rev': False,
            'ecn_ect1_syn_rev': False,
            'ecn_ce_syn_rev': False,
            'ecn_ect0_data_rev': False,
            'ecn_ect1_data_rev': False,
            'ecn_ce_data_rev': False,
        }
        
        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_ecn:
            assert flows[0][key] == expected_ecn[key]
