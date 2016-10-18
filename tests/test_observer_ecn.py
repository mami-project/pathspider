
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import Observer

from pathspider.observer import basic_flow
from pathspider.observer.tcp import TCP_SEC
from pathspider.observer.tcp import TCP_SAE
from pathspider.plugins.ecn import ECN

def test_observer_ecn():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/tcp_ecn.pcap"

    logging.getLogger().setLevel(logging.INFO)

    spider = ECN(1, lturi, None)
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
    assert flow['fwd_syn_flags'] == TCP_SEC
    assert flow['rev_syn_flags'] == TCP_SAE
    assert flow['tcp_connected'] == True
    assert flow['fwd_fin'] == True
    assert flow['rev_fin'] == True
    assert flow['fwd_rst'] == False
    assert flow['rev_rst'] == False
    assert flow['fwd_ez'] == True
    assert flow['rev_ez'] == True
    assert flow['fwd_eo'] == False
    assert flow['rev_eo'] == False
    assert flow['fwd_ce'] == False
    assert flow['rev_ce'] == True

def test_observer_ecn_partial_flow():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/tcp_http.pcap"

    logging.getLogger().setLevel(logging.INFO)

    spider = ECN(1, lturi, None)
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
        assert flow['fwd_ez'] == False
        assert flow['rev_ez'] == False
        assert flow['fwd_eo'] == False
        assert flow['rev_eo'] == False
        assert flow['fwd_ce'] == False
        assert flow['rev_ce'] == False
