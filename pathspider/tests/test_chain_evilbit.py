
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.evil import EvilChain

class TestEvilChain(ChainTestCase):

    def test_chain_evilbit_tcp_none(self):
        test_trace = "evilbit_tcp_none.pcap"
        self.create_observer(test_trace, [EvilChain])

        expected_evil = {
            'evilbit_syn_fwd': False,
            'evilbit_syn_rev': False,
            'evilbit_data_fwd': None,
            'evilbit_data_rev': None,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_evil:
            assert flows[0][key] == expected_evil[key]

    def test_chain_evilbit_udp_none(self):
        test_trace = "evilbit_udp_none.pcap"
        self.create_observer(test_trace, [EvilChain])

        expected_evil = {
            'evilbit_syn_fwd': None,
            'evilbit_syn_rev': None,
            'evilbit_data_fwd': False,
            'evilbit_data_rev': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_evil:
            assert flows[0][key] == expected_evil[key]


    def test_chain_evilbit_tcp_fwd(self):
        test_trace = "evilbit_tcp_fwd.pcap"
        self.create_observer(test_trace, [EvilChain])

        expected_evil = {
            'evilbit_syn_fwd': True,
            'evilbit_syn_rev': False,
            'evilbit_data_fwd': None,
            'evilbit_data_rev': None,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_evil:
            assert flows[0][key] == expected_evil[key]

    def test_chain_evilbit_tcp_rev(self):
        test_trace = "evilbit_tcp_rev.pcap"
        self.create_observer(test_trace, [EvilChain])

        expected_evil = {
            'evilbit_syn_fwd': False,
            'evilbit_syn_rev': True,
            'evilbit_data_fwd': None,
            'evilbit_data_rev': None,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_evil:
            assert flows[0][key] == expected_evil[key]


    def test_chain_evilbit_udp_fwd(self):
        test_trace = "evilbit_udp_fwd.pcap"
        self.create_observer(test_trace, [EvilChain])

        expected_evil = {
            'evilbit_syn_fwd': None,
            'evilbit_syn_rev': None,
            'evilbit_data_fwd': True,
            'evilbit_data_rev': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_evil:
            assert flows[0][key] == expected_evil[key]

    def test_chain_evilbit_udp_rev(self):
        test_trace = "evilbit_udp_rev.pcap"
        self.create_observer(test_trace, [EvilChain])

        expected_evil = {
            'evilbit_syn_fwd': None,
            'evilbit_syn_rev': None,
            'evilbit_data_fwd': False,
            'evilbit_data_rev': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_evil:
            assert flows[0][key] == expected_evil[key]

###########################################################
# Temporarily disabled due to:
# https://github.com/mami-project/pathspider/issues/219
###########################################################
#    def test_chain_evilbit_tcp_no_syn(self):
#        test_trace = "evilbit_tcp_non_syn.pcap"
#        self.create_observer(test_trace, [EvilChain])
#
#        expected_evil = {
#            'evilbit_syn_fwd': None,
#            'evilbit_syn_rev': None,
#            'evilbit_data_fwd': None,
#            'evilbit_data_rev': None,
#        }
#
#        flows = self.run_observer()
#        print(flows)
#        assert len(flows) == 1
#        for key in expected_evil:
#            assert flows[0][key] == expected_evil[key]
###########################################################
