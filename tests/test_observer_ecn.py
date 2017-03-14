
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import Observer

from pathspider.observer.tcp import TCP_SEC
from pathspider.observer.tcp import TCP_SAE
from pathspider.plugins.ecn import ECN

class FakeECNArgs:
    timeout = 5

def test_observer_ecn():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/tcp_ecn.pcap"

    logging.getLogger().setLevel(logging.INFO)

    spider = ECN(1, lturi, FakeECNArgs())
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

    assert len(flows) == 1

    flow = flows[0]
    assert flow['sp'] == 46557
    assert flow['dp'] == 80
    assert flow['tcp_synflags_fwd'] == TCP_SEC
    assert flow['tcp_synflags_rev'] == TCP_SAE
    assert flow['tcp_connected'] == True
    assert flow['tcp_fin_fwd'] == True
    assert flow['tcp_fin_rev'] == True
    assert flow['tcp_rst_fwd'] == False
    assert flow['tcp_rst_rev'] == False
    assert flow['ecn_ect0_fwd'] == True
    assert flow['ecn_ect0_rev'] == True
    assert flow['ecn_ect1_fwd'] == False
    assert flow['ecn_ect1_rev'] == False
    assert flow['ecn_ce_fwd'] == False
    assert flow['ecn_ce_rev'] == True

def test_observer_ecn_partial_flow():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/tcp_http.pcap"

    logging.getLogger().setLevel(logging.INFO)

    spider = ECN(1, lturi, FakeECNArgs())
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

    assert len(flows) == 3

    for flow in flows:
        assert flow['ecn_ect0_fwd'] == False
        assert flow['ecn_ect0_rev'] == False
        assert flow['ecn_ect1_fwd'] == False
        assert flow['ecn_ect1_rev'] == False
        assert flow['ecn_ce_fwd'] == False
        assert flow['ecn_ce_rev'] == False
