
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL
from pathspider.observer import Observer

from pathspider.observer import BasicChain
from pathspider.observer.tcp import TCPChain
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
                 chains=[BasicChain, TCPChain])
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
            assert flow['tcp_synflags_fwd'] == TCP_SYN
            assert flow['tcp_synflags_rev'] == TCP_SYN | TCP_ACK
            assert flow['tcp_connected'] == True
            assert flow['tcp_fin_fwd'] == True
            assert flow['tcp_fin_rev'] == True
            assert flow['tcp_rst_fwd'] == False
            assert flow['tcp_rst_rev'] == False
        if flow['dip'] == "216.239.59.99":
            assert flow['sp'] == 3371
            assert flow['dp'] == 80
            assert flow['tcp_synflags_fwd'] == None
            assert flow['tcp_synflags_rev'] == None
            assert flow['tcp_connected'] == False
            assert flow['tcp_fin_fwd'] == False
            assert flow['tcp_fin_rev'] == False
            assert flow['tcp_rst_fwd'] == False
            assert flow['tcp_rst_rev'] == False
        if flow['dip'] == "145.253.2.203":
            # This is a UDP flow, it won't be merged as there will not have
            # been a job record
            assert flow['sp'] == 3009
            assert flow['dp'] == 53
            assert flow['tcp_synflags_fwd'] == None
            assert flow['tcp_synflags_rev'] == None
            assert flow['tcp_connected'] == False
            assert flow['tcp_fin_fwd'] == False
            assert flow['tcp_fin_rev'] == False
            assert flow['tcp_rst_fwd'] == False
            assert flow['tcp_rst_rev'] == False
        dips.append(flow['dip'])

    assert "65.208.228.223" in dips
    assert "216.239.59.99" in dips
    assert "145.253.2.203" in dips
