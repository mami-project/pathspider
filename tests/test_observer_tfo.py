
import logging
import queue
import threading

import nose

from pathspider.base import SHUTDOWN_SENTINEL

from pathspider.observer import basic_flow
from pathspider.observer.tcp import TCP_SYN
from pathspider.observer.tcp import TCP_SA
from pathspider.plugins.tfo import TFO

class FakeTFOArgs:
    timeout = 5

def test_observer_tfo():
    try:
        import plt # libtrace may not be available
    except:
        raise nose.SkipTest

    lturi = "pcap:tests/testdata/tcp_tfo.pcap"

    logging.getLogger().setLevel(logging.INFO)

    spider = TFO(1, lturi, FakeTFOArgs())
    o = spider.create_observer()
    q = queue.Queue()
    t = threading.Thread(target=o.run_flow_enqueuer,
                         args=(q,),
                         daemon=True)
    t.start()

    tfo_flow_tested = False
    non_tfo_flow_tested = False

    while True:
        f = q.get()
        if f == SHUTDOWN_SENTINEL:
            break
        if (f['sip'] == "2a03:b0c0:3:d0::1dfd:4001" and
            f['dip'] == "2a00:1450:4009:813::2009" and
            f['sp'] == 57469):
            assert f['tcp_fin_fwd'] == True
            assert f['tcp_rst_fwd'] == True
            assert f['tcp_synflags_fwd'] == TCP_SYN
            assert f['oct_fwd'] == 397
            assert f['oct_rev'] == 1045
            assert f['pkt_fwd'] == 5
            assert f['pkt_rev'] == 4
            assert f['proto'] == 6
            assert f['tcp_fin_rev'] == True
            assert f['tcp_rst_rev'] == False
            assert f['tcp_synflags_rev'] == TCP_SA
            assert f['tcp_connected'] == True
            assert f['tfo_ack'] == 4042009891
            assert f['tfo_ackclen'] == 0
            assert f['tfo_ackkind'] == 0
            assert f['tfo_dlen'] == 41
            assert f['tfo_seq'] == 4042009849
            assert f['tfo_synclen'] == 8
            assert f['tfo_synkind'] == 254
            tfo_flow_tested = True
        if (f['sip'] == "2a03:b0c0:3:d0::1dfd:4001" and
            f['dip'] == "2a00:1450:4008:802::2003" and
            f['sp'] == 46802):
            print(f)
            assert f['tcp_fin_fwd'] == True
            assert f['tcp_rst_fwd'] == False
            assert f['tcp_synflags_fwd'] == TCP_SYN
            assert f['oct_fwd'] == 296
            assert f['oct_rev'] == 152
            assert f['pkt_fwd'] == 4
            assert f['pkt_rev'] == 2
            assert f['proto'] == 6
            assert f['tcp_fin_rev'] == True
            assert f['tcp_rst_rev'] == False
            assert f['tcp_synflags_rev'] == TCP_SA
            assert f['tcp_connected'] == True
            assert f['tfo_ack'] == 0
            assert f['tfo_ackclen'] == 0
            assert f['tfo_ackkind'] == 0
            assert f['tfo_dlen'] == 0
            assert f['tfo_seq'] == 0
            assert f['tfo_synclen'] == 0
            assert f['tfo_synkind'] == 0
