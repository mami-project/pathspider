import os

from collections import namedtuple

from pathspider.plugins.udpzero import UDPZero

TestArgs = namedtuple('TestArgs', ['connect'])
job = {'dip': '192.0.2.4', 'dp': 80, 'domain': 'example.com'}

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
