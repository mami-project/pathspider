import pycurl

from pathspider.base import CONN_OK
from pathspider.base import CONN_FAILED
from pathspider.plugins.h2 import H2
from pathspider.helpers.http import connect_http
from pathspider.helpers.http import connect_https
from pathspider.chains.basic import BasicChain
from pathspider.chains.tcp import TCPChain
from pathspider.tests.chains import ChainTestCase

def test_plugin_h2_combine():
    test_groups = [
                   (CONN_OK, CONN_OK,   "h2.connectivity.works"),
                   (CONN_FAILED, CONN_OK,  "h2.connectivity.transient"),
                   (CONN_OK, CONN_FAILED,  "h2.connectivity.broken"),
                   (CONN_FAILED, CONN_FAILED,  "h2.connectivity.offline")
                  ]
    for group in test_groups:
        flows = [              
                 {'spdr_state': group[0]},
                 {'spdr_state': group[1], 'http_info': {pycurl.INFO_HTTP_VERSION: pycurl.CURL_HTTP_VERSION_2_0}}
                ]
        spider = H2(0, "", None)
        conditions = spider.combine_flows(flows)
        assert group[2] in conditions

    upgrade_groups = [ 
                      ('h2.upgrade.success', pycurl.CURL_HTTP_VERSION_2_0),
                      ('h2.upgrade.failed', None),
                     ]
    for group in upgrade_groups:
        flows =  [
                 {'spdr_state': CONN_OK},
                 {'spdr_state': CONN_OK, 'http_info': {pycurl.INFO_HTTP_VERSION : group[1]}}
                ]
        spider = H2(0, "", None)
        conditions = spider.combine_flows(flows)
        assert group[0] in conditions
