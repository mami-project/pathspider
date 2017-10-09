
import pkg_resources

from pathspider.cmd.measure import job_feeder_csv as job_feeder

class FakeSpider:
    def __init__(self):
        self.was_shutdown = False
        self.jobs = []

    def add_job(self, row):
        self.jobs.append(row)

    def shutdown(self):
        self.was_shutdown = True

def test_job_feeder_csv_webtest():
    spider = FakeSpider()

    expected_jobs = [{'dip': '160.85.31.173', 'dp': '80', 'domain': 'mami-project.eu', 'rank': '1'},
                     {'dip': '139.133.210.32', 'dp': '80', 'domain': 'erg.abdn.ac.uk', 'rank': '2'},
                     {'dip': '2001:630:241:210:569f:35ff:fe0a:116a', 'dp': '80', 'domain': 'erg.abdn.ac.uk',  'rank': '3'},
                     {'dip': '129.132.52.158', 'dp': '80', 'domain': 'ecn.ethz.ch', 'rank': '4'},
                     {'dip': '2001:67c:10ec:36c2::61', 'dp': '80', 'domain': 'ecn.ethz.ch', 'rank': '5'},
                     {'dip': '139.133.1.4', 'dp': '80', 'domain': 'abdn.ac.uk', 'rank': '6'}]

    job_feeder(pkg_resources.resource_filename("pathspider", "tests/data/webtest.csv"), spider)
    assert spider.was_shutdown
    print (spider.jobs)
    print (expected_jobs)
    assert spider.jobs == expected_jobs

def test_job_feeder_csv_webtest_newline():
    spider = FakeSpider()

    expected_jobs = [{'dip': '160.85.31.173', 'dp': '80', 'domain': 'mami-project.eu', 'rank': '1'},
                     {'dip': '139.133.210.32', 'dp': '80', 'domain': 'erg.abdn.ac.uk', 'rank': '2'},
                     {'dip': '2001:630:241:210:569f:35ff:fe0a:116a', 'dp': '80', 'domain': 'erg.abdn.ac.uk',  'rank': '3'},
                     {'dip': '129.132.52.158', 'dp': '80', 'domain': 'ecn.ethz.ch', 'rank': '4'},
                     {'dip': '2001:67c:10ec:36c2::61', 'dp': '80', 'domain': 'ecn.ethz.ch', 'rank': '5'},
                     {'dip': '139.133.1.4', 'dp': '80', 'domain': 'abdn.ac.uk', 'rank': '6'}]

    job_feeder(pkg_resources.resource_filename("pathspider", "tests/data/webtest_newline.csv"), spider)
    assert spider.was_shutdown
    assert spider.jobs == expected_jobs

def test_job_feeder_csv_webtest_duplicates():
    spider = FakeSpider()

    expected_jobs = [{'dip': '160.85.31.173', 'dp': '80', 'domain': 'mami-project.eu', 'rank': '1'},
                     {'dip': '139.133.210.32', 'dp': '80', 'domain': 'erg.abdn.ac.uk', 'rank': '2'},
                     {'dip': '2001:630:241:210:569f:35ff:fe0a:116a', 'dp': '80', 'domain': 'erg.abdn.ac.uk',  'rank': '3'},
                     {'dip': '129.132.52.158', 'dp': '80', 'domain': 'ecn.ethz.ch', 'rank': '4'},
                     {'dip': '2001:67c:10ec:36c2::61', 'dp': '80', 'domain': 'ecn.ethz.ch', 'rank': '5'},
                     {'dip': '139.133.1.4', 'dp': '80', 'domain': 'abdn.ac.uk', 'rank': '6'}]

    job_feeder(pkg_resources.resource_filename("pathspider", "tests/data/webtest_duplicates.csv"), spider)
    assert spider.was_shutdown
    print (spider.jobs)
    print (expected_jobs)
    assert spider.jobs == expected_jobs
