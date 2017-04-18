
from pathspider.tests.chains import ChainTestCase

class ObserverMatchingTest(ChainTestCase):

    def test_observer_random_flowcount(self):
        test_trace = "random.pcap"
        self.create_observer(test_trace, [])
        flows = self.run_observer()
        assert len(flows) == 0
    
    def test_observer_real_flowcount(self):
        test_trace = "real.pcap"
        self.create_observer(test_trace, [])
        flows = self.run_observer()
        assert len(flows) == 6317
    
    def test_observer_icmp_ttl_flowcount(self):
        test_trace = "icmp_ttl.pcap"
        self.create_observer(test_trace, [])
        flows = self.run_observer()
        assert len(flows) == 297
