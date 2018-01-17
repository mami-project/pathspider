from pathspider.chains.ecn import ECNChain
from pathspider.plugins.ecn import ECN
from pathspider.tests.chains import ChainTestCase
from pathspider.chains.tcp import TCP_SA
from pathspider.base import CONN_OK
from pathspider.base import CONN_FAILED
from pathspider.chains.tcp import TCP_SAE
from pathspider.chains.tcp import TCP_SAEC
from pathspider.chains.tcp import TCP_SYN

def test_plugin_ecn_not_observed():
    flows = [
             {'observed': True, 'spdr_state': CONN_OK},
             {'observed': False, 'spdr_state': CONN_OK}
            ]
    conditions = ECN.combine_flows(None, flows)
    assert "pathspider.not_observed" in conditions

def test_plugin_ecn_combine():
    test_groups = [
                   (CONN_OK,  CONN_OK,  "ecn.connectivity.works"),
                   (CONN_OK,  CONN_FAILED, "ecn.connectivity.broken"),
                   (CONN_FAILED, CONN_OK,  "ecn.connectivity.transient"),
                   (CONN_FAILED, CONN_FAILED, "ecn.connectivity.offline")
                  ]
    for group in test_groups:
        flow = [
                {'observed': True, 'spdr_state': group[0], 'tcp_connected': False},
                {'observed': True, 'spdr_state': group[1], 'tcp_connected': False}
               ]

        conditions = ECN.combine_flows(None, flow)
        assert group[2] in conditions

    test_groups_ecn = [
                       (True,  TCP_SAE,  "ecn.negotiation.succeeded"),
                       (True,  TCP_SAEC, "ecn.negotiation.reflected"),
                       (True,  TCP_SYN,     "ecn.negotiation.failed"),
                      ]

    for group in test_groups_ecn:
        flow = [
                {'observed': True, 'spdr_state': CONN_OK},
                {'observed': True, 'spdr_state': CONN_OK, 'tcp_connected': group[0], 'tcp_synflags_rev': group[1], 'ecn_ect0_syn_rev': False, 'ecn_ect1_syn_rev': False, 'ecn_ce_syn_rev': False, 'ecn_ect0_data_rev': False, 'ecn_ect1_data_rev': False, 'ecn_ce_data_rev': False }
               ]

        conditions = ECN.combine_flows(None, flow)
        assert group[2] in conditions

    test_groups_mark = [
                       (True, "ecn.ipmark.ect0.seen"),
                       (False, "ecn.ipmark.ect0.not_seen"),
                       (True, "ecn.ipmark.ect1.seen"),
                       (False, "ecn.ipmark.ect1.not_seen"),
                       (True, "ecn.ipmark.ce.seen"),
                       (False, "ecn.ipmark.ce.not_seen")
                      ]
    for group in test_groups_mark:
        flow = [
                {'observed': True, 'spdr_state': CONN_OK},
                {'observed': True, 'spdr_state': CONN_OK, 'tcp_connected': True, 'tcp_synflags_rev': TCP_SAE, 'ecn_ect0_syn_rev': group[0], 'ecn_ect1_syn_rev': group[0], 'ecn_ce_syn_rev': group[0], 'ecn_ect0_data_rev': group[0], 'ecn_ect1_data_rev': group[0], 'ecn_ce_data_rev': group[0] }
               ]
        conditions = ECN.combine_flows(None, flow)
        assert group[1] in conditions
