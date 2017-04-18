
from pathspider.tests.chains import ChainTestCase

from pathspider.chains.dns import DNSChain

class TestDNSChain(ChainTestCase):

    def test_chain_dns_valid_response(self):
        test_trace = "dns_valid_response.pcap"
        self.create_observer(test_trace, [DNSChain])

        expected_dns = {
            'dns_response_valid': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_dns:
            assert flows[0][key] == expected_dns[key]

    def test_chain_dns_valid_response_tcp(self):
        test_trace = "dns_valid_response_tcp.pcap"
        self.create_observer(test_trace, [DNSChain])

        expected_dns = {
            'dns_response_valid': True,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        print(flows)

        for key in expected_dns:
            assert flows[0][key] == expected_dns[key]

    def test_chain_dns_no_response(self):
        test_trace = "dns_no_response.pcap"
        self.create_observer(test_trace, [DNSChain])

        expected_dns = {
            'dns_response_valid': False,
        }

        flows = self.run_observer()
        assert len(flows) == 1

        for key in expected_dns:
            assert flows[0][key] == expected_dns[key]
