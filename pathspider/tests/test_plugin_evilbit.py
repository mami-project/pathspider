
from collections import namedtuple
from tempfile import NamedTemporaryFile

from scapy.all import wrpcap

from pathspider.chains.evil import EvilChain
from pathspider.plugins.evilbit import EvilBit
from pathspider.tests.chains import ChainTestCase
from pathspider.chains.tcp import TCP_SA 

TestArgs = namedtuple('TestArgs', ['connect'])
job = {'dip': '192.0.2.4', 'dp': 80, 'domain': 'example.com'}

class TestPluginEvilBitForgeObserve(ChainTestCase):

    def test_plugin_evilbit_forge_observer(self):
        for connect in EvilBit.connect_supported:
            spider = EvilBit(0, "", TestArgs(connect=connect))
            packets = []

            for seq in range(0, spider.packets):
                packets.append(spider.forge(job, seq))
            assert len(packets) == 2

            expected_flows = [
              {
                'evilbit_syn_fwd': False if connect == "tcpsyn" else None,
                'evilbit_syn_rev': None,
                'evilbit_data_fwd': False if connect == "dnsudp" else None,
                'evilbit_data_rev': None
              }, {
                'evilbit_syn_fwd': True if connect == "tcpsyn" else None,
                'evilbit_syn_rev': None,
                'evilbit_data_fwd': True if connect == "dnsudp" else None,
                'evilbit_data_rev': None
              }
            ]

            with NamedTemporaryFile() as test_trace:
                for idx in range(0, 2):
                    wrpcap(test_trace.name, [packets[idx]])
                    self.create_observer(test_trace.name, [EvilChain])
        
                    flows = self.run_observer()
                    assert len(flows) == 1
        
                    for key in expected_flows[idx]:
                        print(key + ">>" + str(flows[0][key]) + ":" +
                              str(expected_flows[0][key]))
                        assert flows[0][key] == expected_flows[idx][key]


def test_plugin_evilbit_forge_diff():
    for connect in EvilBit.connect_supported:
        spider = EvilBit(0, "", TestArgs(connect=connect))
        packets = []

        for seq in range(0, spider.packets):
            packets.append(spider.forge(job, seq))
        assert len(packets) == 2

        packets[0].flags = 'evil'
        packets[0].payload.sport = packets[1].payload.sport

        print(packets[0].summary())
        print(packets[1].summary())

        assert bytes(packets[0]) == bytes(packets[1])

def test_plugin_evilbit_combine_not_observed():
    flows = [
             {'observed': True},
             {'observed': False}
            ]
    spider = EvilBit(0, "", None)
    conditions = spider.combine_flows(flows)
    assert "pathspider.not_observed" in conditions


def test_plugin_evilbit_combine():
    test_groups = [
                   (True,  True,  "evilbit.connectivity.works", TCP_SA, TCP_SA),
                   (True,  False, "evilbit.connectivity.broken", TCP_SA, None, ),
                   (False, True,  "evilbit.connectivity.transient", None, TCP_SA),
                   (False, False, "evilbit.connectivity.offline", None, None)
                  ]
    for group in test_groups:
        flows = [
                [
                 {'observed': True, 'tcp_synflags_rev': group[3]},
                 {'observed': True, 'tcp_synflags_rev': group[4], 'evilbit_syn_rev': True}
                ],
                [
                 {'observed': True, 'dns_response_valid': group[0]},
                 {'observed': True, 'dns_response_valid': group[1], 'evilbit_data_rev': True}
                ]]
        
        for flow in [0,1]:
            spider = EvilBit(0, "", TestArgs(connect=EvilBit.connect_supported[flow]))
            conditions = EvilBit.combine_flows(spider, flows[flow])
            assert group[2] in conditions


    evil_groups = [ ('evilbit.mark.seen', True),
                    ('evilbit.mark.not_seen', False)
                  ]
    for group in evil_groups:
        flows = [
                [
                 {'observed': True, 'tcp_synflags_rev': TCP_SA},
                 {'observed': True, 'tcp_synflags_rev': TCP_SA, 'evilbit_syn_rev': group[1]}
                ],
                [
                 {'observed': True, 'dns_response_valid': True},
                 {'observed': True, 'dns_response_valid': True, 'evilbit_data_rev': group[1]}
                ]]
        for flow in [0,1]:
            spider = EvilBit(0, "", TestArgs(connect=EvilBit.connect_supported[flow]))
            conditions = EvilBit.combine_flows(spider, flows[flow])
            assert group[0] in conditions

            
