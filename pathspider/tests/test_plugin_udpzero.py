
from collections import namedtuple
from tempfile import NamedTemporaryFile

from scapy.all import wrpcap

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
                wrpcap(test_trace.name, [packets[idx]])
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
