from pathspider.chains.mss import MSSChain
from pathspider.plugins.mss import MSS
from pathspider.tests.chains import ChainTestCase
from pathspider.chains.tcp import TCP_SA 

def test_plugin_mss_combine_not_observed():
    flows = [
             {'observed': False, 'tcp_connected': False},
             {'observed': True, 'tcp_connected': False}
            ]
    spider = MSS(0, "", None)
    conditions = spider.combine_flows(flows)
    assert "pathspider.not_observed" in conditions


def test_plugin_mss_combine():
    test_groups = [
                   (True,  "mss.connectivity.online"),
                   (False, "mss.connectivity.offline")
                  ]
    for group in test_groups:
        flows = [              
                 {'observed': True, 'tcp_connected': group[0], 'mss_value_fwd': None , 'mss_len_rev': None, 'mss_value_rev': None}
                ]
        
        spider = MSS(0, "", None)
        conditions = spider.combine_flows(flows)
        assert group[1] in conditions
        if "mss.connectivity.online" in conditions:
            assert 'mss.option.received.absent' in conditions
         

    mss_groups = [ 
                  ('mss.option.received.unchanged', 1460, 1460),
                  ('mss.option.received.inflated', 1440, 1460),
                  ('mss.option.received.deflated', 1460, 1440)
                 ]
    for group in mss_groups:
        flows =  [
                 {'observed': True, 'tcp_connected': True, 'mss_value_fwd': group[1], 'mss_len_rev': 4, 'mss_value_rev': group[2]}
                ]
        spider = MSS(0, "", None)
        conditions = spider.combine_flows(flows)
        print(group)
        print(conditions)
        assert group[0] in conditions
