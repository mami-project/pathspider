
import logging
import queue
import multiprocessing as mp
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.base import QUEUE_SIZE
from pathspider.observer import Observer
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

def test_observer_icmp_ttl_flowcount():
    lturi = "pcap:tests/testdata/icmp_ttl.pcap"
    # the following assertion will break if we take TCP sequence numbers
    # into consideration in the observer
    assert _test_observer(lturi) == 297

def test_observer_icmp_unreachable_flowcount():
    lturi = "pcap:tests/testdata/icmp_unreachable.pcap"
    assert _test_observer(lturi) == 2

def test_observer_shutdown():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    flowqueue = mp.Queue(QUEUE_SIZE)
    observer_shutdown_queue = mp.Queue(QUEUE_SIZE)

    observer = Observer("pcap:tests/testdata/random.pcap")
    observer_process = mp.Process(
        args=(flowqueue,
              observer_shutdown_queue),
        target=observer.run_flow_enqueuer,
        name='observer',
        daemon=True)
    observer_process.start()

    observer_shutdown_queue.put(True)

    assert flowqueue.get(True, timeout=3) == SHUTDOWN_SENTINEL

    observer_process.join(3)

    assert not observer_process.is_alive()
