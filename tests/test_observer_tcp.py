
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import Observer

from pathspider.observer import basic_flow
from pathspider.observer.tcp import tcp_setup
from pathspider.observer.tcp import tcp_handshake
from pathspider.observer.tcp import tcp_complete
from pathspider.observer.tcp import TCP_SYN
from pathspider.observer.tcp import TCP_ACK

def test_observer_tcp():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/tcp_http.pcap"

    logging.getLogger().setLevel(logging.INFO)

    o = Observer(lturi,
                 new_flow_chain=[basic_flow, tcp_setup],
                 tcp_chain=[tcp_handshake, tcp_complete])
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

    print(flows)

    dips = []
    for flow in flows:
        if flow['dip'] == "65.208.228.223":
            assert flow['sp'] == 3372
            assert flow['dp'] == 80
            assert flow['fwd_syn_flags'] == TCP_SYN
            assert flow['rev_syn_flags'] == TCP_SYN | TCP_ACK
            assert flow['tcp_connected'] == True
            assert flow['fwd_fin'] == True
            assert flow['rev_fin'] == True
            assert flow['fwd_rst'] == False
            assert flow['rev_rst'] == False
        if flow['dip'] == "216.239.59.99":
            assert flow['sp'] == 3371
            assert flow['dp'] == 80
            assert flow['fwd_syn_flags'] == None
            assert flow['rev_syn_flags'] == None
            assert flow['tcp_connected'] == False
            assert flow['fwd_fin'] == False
            assert flow['rev_fin'] == False
            assert flow['fwd_rst'] == False
            assert flow['rev_rst'] == False
        if flow['dip'] == "145.253.2.203":
            # This is a UDP flow, it won't be merged as there will not have
            # been a job record
            assert flow['sp'] == 3009
            assert flow['dp'] == 53
            assert flow['fwd_syn_flags'] == None
            assert flow['rev_syn_flags'] == None
            assert flow['tcp_connected'] == False
            assert flow['fwd_fin'] == False
            assert flow['rev_fin'] == False
            assert flow['fwd_rst'] == False
            assert flow['rev_rst'] == False
        dips.append(flow['dip'])

    assert "65.208.228.223" in dips
    assert "216.239.59.99" in dips
    assert "145.253.2.203" in dips
