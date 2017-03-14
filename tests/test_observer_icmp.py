
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import Observer

from pathspider.observer import BasicChain
from pathspider.observer.icmp import ICMPChain

def test_observer_icmp_unreachable():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/icmp_unreachable.pcap"

    logging.getLogger().setLevel(logging.INFO)

    o = Observer(lturi,
                 chains=[BasicChain, ICMPChain])
    q = queue.Queue()
    t = threading.Thread(target=o.run_flow_enqueuer,
                         args=(q,),
                         daemon=True)
    t.start()

    unreachables = [
        '172.20.152.190',
        ]

    while True:
        f = q.get()
        if f == SHUTDOWN_SENTINEL:
            break
        print(f)
        assert f['icmp_unreachable'] == (f['dip'] in unreachables)
