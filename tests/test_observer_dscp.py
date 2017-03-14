
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import Observer

from pathspider.plugins.dscp import DSCP

class FakeDSCPArgs:
    timeout = 5
    codepoint = None

def test_observer_dscp():
    # FIXME: This test only stresses the plugin, doesn't actually check the
    # results are correct, just that it doesn't crash.

    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/icmp_ttl.pcap"

    logging.getLogger().setLevel(logging.INFO)

    spider = DSCP(1, lturi, FakeDSCPArgs())
    o = spider.create_observer()
    q = queue.Queue()
    t = threading.Thread(target=o.run_flow_enqueuer,
                         args=(q,),
                         daemon=True)
    t.start()

    flows = []
    while True:
        f = q.get()
        if f == SHUTDOWN_SENTINEL:
            break
        flows.append(f)
