
from collections import namedtuple
from tempfile import NamedTemporaryFile

from scapy.all import wrpcap
from scapy.all import Ether

from pathspider.chains.udp import UDPChain
from pathspider.plugins.udpzero import UDPZero
from pathspider.tests.chains import ChainTestCase

TestArgs = namedtuple('TestArgs', ['connect'])
job = {'dip': '192.0.2.4', 'dp': 80, 'domain': 'example.com'}

class TestPluginUDPZeroForgeObserve(ChainTestCase):

    def test_plugin_udpzero_forge_observer(self):
        spider = UDPZero(0, "", TestArgs(connect="dnsudp"))
        packets = []

        for seq in range(0, spider.packets):
            packets.append(spider.forge(job, seq))
        assert len(packets) == 2

        expected_flows = [
          {
            'udp_zero_checksum_fwd': False,
            'udp_zero_checksum_rev': None
          }, {
            'udp_zero_checksum_fwd': True,
            'udp_zero_checksum_rev': None
          }
        ]

        with NamedTemporaryFile() as test_trace:
            for idx in range(0, 2):
                wrpcap(test_trace.name, [Ether()/packets[idx]])
                self.create_observer(test_trace.name, [UDPChain])

                flows = self.run_observer()
                assert len(flows) == 1

                for key in expected_flows[idx]:
                    print(key + ">>" + str(flows[0][key]) + ":" +
                          str(expected_flows[0][key]))
                    assert flows[0][key] == expected_flows[idx][key]

def test_plugin_udpzero_forge_diff():
    spider = UDPZero(0, "", TestArgs(connect="dnsudp"))
    packets = []

    for seq in range(0, spider.packets):
        packets.append(spider.forge(job, seq))
    assert len(packets) == 2

    packets[0].payload.chksum = 0
    packets[0].payload.sport = packets[1].payload.sport

    print(packets[0].summary())
    print(packets[1].summary())

    assert bytes(packets[0]) == bytes(packets[1])

def test_plugin_udpzero_combine():
    test_groups = [
                   (True,  True,  "udpzero.connectivity.works"),
                   (True,  False, "udpzero.connectivity.broken"),
                   (False, True,  "udpzero.connectivity.transient"),
                   (False, False, "udpzero.connectivity.offline")
                  ]
    for group in test_groups:
        flows = [
                 {'observed': True, 'dns_response_valid': group[0]},
                 {'observed': True, 'dns_response_valid': group[1]}
                ]
        spider = UDPZero(0, "", None)
        conditions = spider.combine_flows(flows)
        assert group[2] in conditions

def test_plugin_udpzero_combine_not_observed():
    for valid in [True, False]:
        flows = [
                 {'observed': True, 'dns_response_valid': valid},
                 {'observed': False}
                ]
        spider = UDPZero(0, "", None)
        conditions = spider.combine_flows(flows)
        assert "pathspider.not_observed" in conditions
