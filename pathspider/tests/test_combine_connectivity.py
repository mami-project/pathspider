from nose.tools import assert_equal

from pathspider.base import Spider

def test_combine_connectivity():
    spider = Spider(0, "", None, False)

    combinations = [(True, True, "spider.connectivity.works", None),
                    (True, False, "spider.connectivity.broken", None),
                    (False, True, "spider.connectivity.transient", None),
                    (False, False, "spider.connectivity.offline", None),
                    (True, None, "spider.connectivity.online", None),
                    (True, True, "dummy.connectivity.works", "dummy")]

    for combination in combinations:
        assert_equal(spider.combine_connectivity(combination[0],
                       combination[1], prefix=combination[3]), combination[2])
