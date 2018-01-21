
from collections import namedtuple
from tempfile import NamedTemporaryFile

from scapy.all import wrpcap

from pathspider.chains.dscp import DSCPChain
from pathspider.plugins.dscp import DSCP
from pathspider.tests.chains import ChainTestCase
from pathspider.base import CONN_OK
from pathspider.base import CONN_FAILED

def test_plugin_dscp_combine_not_observed():
    for valid in [True, False]:
        flows = [
                 {'observed': True},
                 {'observed': False}
                ]
        spider = DSCP(0, "", None)
        conditions = spider.combine_flows(flows)
        assert "pathspider.not_observed" in conditions

def test_plugin_dscp_combine():
    test_groups = [
                   (CONN_OK,  CONN_OK,  "dscp.46.connectivity.works"),
                   (CONN_OK,  CONN_FAILED, "dscp.46.connectivity.broken"),
                   (CONN_FAILED, CONN_OK,  "dscp.46.connectivity.transient"),
                   (CONN_FAILED, CONN_FAILED, "dscp.46.connectivity.offline")
                  ]
    for group in test_groups:
        flows = [
                 {'observed': True, 'spdr_state': group[0], 'dscp_mark_syn_fwd': 0, 'dscp_mark_data_fwd': 0, 'dscp_mark_syn_rev': 0, 'dscp_mark_data_rev': 0},
                 {'observed': True, 'spdr_state': group[1], 'dscp_mark_syn_fwd': 46, 'dscp_mark_data_fwd': 46, 'dscp_mark_syn_rev': 46, 'dscp_mark_data_rev': 46}
                ]
        spider = DSCP(0, "", None)
        conditions = spider.combine_flows(flows)
        print(group)
        print(conditions)
        assert group[2] in conditions
        if 'dscp.46.connectivity.works' in conditions:
            assert 'dscp.0.replymark:0' in conditions
            assert 'dscp.46.replymark:46' in conditions


