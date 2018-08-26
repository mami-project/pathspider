from nose.tools import assert_equals

from pathspider.plugins.ecn import ECN
from pathspider.plugins.dscp import DSCP
from pathspider.plugins.evilbit import EvilBit

def test_ecn_test_count():
    """
    This test checks that the ECN, DSCP and EvilBit plugins are all found
    to have 2 tests each by the `_get_test_count(self)` function. These plugins
    are used to have one Sync, Desync and Forge spider each.
    """

    for test_spider in [ECN, DSCP, EvilBit]:
        print("Trying " + test_spider.name)
        spider = test_spider(0, "", None, False)
        assert_equals(spider._get_test_count(), 2)
