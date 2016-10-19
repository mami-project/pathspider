
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import simple_observer

def _test_observer(lturi):
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    logging.getLogger().setLevel(logging.INFO)

    o = simple_observer(lturi)
    q = queue.Queue()
    t = threading.Thread(target=o.run_flow_enqueuer,
                         args=(q,),
                         daemon=True)
    t.start()

    flowcount = 0
    while True:
        f = q.get()
        if f == SHUTDOWN_SENTINEL:
            break
        flowcount += 1

    return flowcount

def test_observer_random_flowcount():
    lturi = "pcap:tests/testdata/random.pcap"
    assert _test_observer(lturi) == 0

def test_observer_real_flowcount():
    lturi = "pcap:tests/testdata/real.pcap"
    assert _test_observer(lturi) == 6317

def test_observer_icmp_flowcount():
    lturi = "pcap:tests/testdata/icmp.pcap"
    assert _test_observer(lturi) == 1

def test_observer_icmp_unreachable_flowcount():
    lturi = "pcap:tests/testdata/icmp_unreachable.pcap"
    assert _test_observer(lturi) == 2
