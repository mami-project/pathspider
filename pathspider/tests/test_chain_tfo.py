
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.tfo import TFOChain

class TestTFOChain(ChainTestCase):

    def test_chain_tfo_cookie_request_expa(self):
        test_trace = "tfo_cookie_request.pcap"
        self.create_observer(test_trace, [TFOChain])

        expected_tfo = {
            'tfo_ack': 3865413713,
            'tfo_ackclen': 8,
            'tfo_ackkind': 254,
            'tfo_dlen': 0,
            'tfo_seq': 3865413712,
            'tfo_synclen': 0,
            'tfo_synkind': 254,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        print(flows)
        print(expected_tfo)

        for key in expected_tfo:
            assert flows[0][key] == expected_tfo[key]

    def test_chain_tfo_data_on_syn_expa(self):
        test_trace = "tfo_data_on_syn.pcap"
        self.create_observer(test_trace, [TFOChain])

        expected_tfo = {
            'tfo_ack': 3108342141,
            'tfo_ackclen': 0,
            'tfo_ackkind': 0,
            'tfo_dlen': 39,
            'tfo_seq': 3108342101,
            'tfo_synclen': 8,
            'tfo_synkind': 254,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        print(flows)
        print(expected_tfo)

    def test_chain_tfo_cookie_request_expb(self):
        test_trace = "tfo_cookie_request_b.pcap"
        self.create_observer(test_trace, [TFOChain])

        expected_tfo = {
            'tfo_ack': 3865413713,
            'tfo_ackclen': 8,
            'tfo_ackkind': 255,
            'tfo_dlen': 0,
            'tfo_seq': 3865413712,
            'tfo_synclen': 0,
            'tfo_synkind': 255,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        print(flows)
        print(expected_tfo)

        for key in expected_tfo:
            assert flows[0][key] == expected_tfo[key]

    def test_chain_tfo_data_on_syn_expb(self):
        test_trace = "tfo_data_on_syn_b.pcap"
        self.create_observer(test_trace, [TFOChain])

        expected_tfo = {
            'tfo_ack': 3108342141,
            'tfo_ackclen': 0,
            'tfo_ackkind': 0,
            'tfo_dlen': 39,
            'tfo_seq': 3108342101,
            'tfo_synclen': 8,
            'tfo_synkind': 255,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        print(flows)
        print(expected_tfo)


        for key in expected_tfo:
            assert flows[0][key] == expected_tfo[key]
