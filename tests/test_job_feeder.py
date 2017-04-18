
from pathspider.cmd.measure import job_feeder

class FakeSpider:
    def __init__(self):
        self.was_shutdown = False
        self.jobs = []

    def add_job(self, row):
        self.jobs.append(row)

    def shutdown(self):
        self.was_shutdown = True

def test_job_feeder_webtest():
    spider = FakeSpider()

    expected_jobs = [{'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '888508', 'domain': 'smartcarsinc.com', 'dip': '12.54.244.146', 'info': {'Cached': '2017-02-24T10:25:14.82660325Z', 'ASN': 7018, 'CountryCode': 'US-VA', 'Prefix': '12.0.0.0/9'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '935244', 'domain': 'jesionowa-40.pl', 'dip': '148.251.67.142', 'info': {'Cached': '2017-02-24T10:25:09.67184801Z', 'ASN': 24940, 'CountryCode': 'DE', 'Prefix': '148.251.0.0/16'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '774975', 'domain': 'granjasantaisabel.com', 'dip': '62.149.128.151', 'info': {'Cached': '2017-02-24T10:25:09.206038319Z', 'ASN': 31034, 'CountryCode': 'IT', 'Prefix': '62.149.128.0/19'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '307350', 'domain': 'bestpartyweb.info', 'dip': '104.27.185.20', 'info': {'Cached': '2017-02-24T10:25:14.645460693Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.27.176.0/20'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '499521', 'domain': 'nationalgallery.sg', 'dip': '104.20.2.18', 'info': {'Cached': '2017-02-24T10:25:06.966867911Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.20.0.0/20'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '872557', 'domain': 'smglnc.blogspot.com', 'dip': '2a00:1450:4001:81e::2001', 'info': {'Cached': '2017-02-24T10:25:20.097217525Z', 'ASN': 15169, 'CountryCode': 'IE', 'Prefix': '2a00:1450:4001::/48'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '727500', 'domain': 'choisirunmedecin.com', 'dip': '144.76.61.23', 'info': {'Cached': '2017-02-24T10:25:09.688636273Z', 'ASN': 24940, 'CountryCode': 'DE', 'Prefix': '144.76.0.0/16'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '307350', 'domain': 'bestpartyweb.info', 'dip': '104.27.184.20', 'info': {'Cached': '2017-02-24T10:25:14.645460693Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.27.176.0/20'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '499521', 'domain': 'nationalgallery.sg', 'dip': '104.20.3.18', 'info': {'Cached': '2017-02-24T10:25:06.966867911Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.20.0.0/20'}}, {'dp': 80, 'lookupType': 'host', 'lookupAttempts': 1, 'rank': '774975', 'domain': 'granjasantaisabel.com', 'dip': '62.149.128.74', 'info': {'Cached': '2017-02-24T10:25:09.206038319Z', 'ASN': 31034, 'CountryCode': 'IT', 'Prefix': '62.149.128.0/19'}}]

    job_feeder("examples/webtest.ndjson", spider)
    assert spider.was_shutdown
    assert spider.jobs == expected_jobs

def test_job_feeder_webtest_newline():
    spider = FakeSpider()

    expected_jobs = [{'lookupType': 'host', 'lookupAttempts': 1, 'rank': '888508', 'domain': 'smartcarsinc.com', 'dip': '12.54.244.146', 'info': {'Cached': '2017-02-24T10:25:14.82660325Z', 'ASN': 7018, 'CountryCode': 'US-VA', 'Prefix': '12.0.0.0/9'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '935244', 'domain': 'jesionowa-40.pl', 'dip': '148.251.67.142', 'info': {'Cached': '2017-02-24T10:25:09.67184801Z', 'ASN': 24940, 'CountryCode': 'DE', 'Prefix': '148.251.0.0/16'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '774975', 'domain': 'granjasantaisabel.com', 'dip': '62.149.128.151', 'info': {'Cached': '2017-02-24T10:25:09.206038319Z', 'ASN': 31034, 'CountryCode': 'IT', 'Prefix': '62.149.128.0/19'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '307350', 'domain': 'bestpartyweb.info', 'dip': '104.27.185.20', 'info': {'Cached': '2017-02-24T10:25:14.645460693Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.27.176.0/20'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '499521', 'domain': 'nationalgallery.sg', 'dip': '104.20.2.18', 'info': {'Cached': '2017-02-24T10:25:06.966867911Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.20.0.0/20'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '872557', 'domain': 'smglnc.blogspot.com', 'dip': '2a00:1450:4001:81e::2001', 'info': {'Cached': '2017-02-24T10:25:20.097217525Z', 'ASN': 15169, 'CountryCode': 'IE', 'Prefix': '2a00:1450:4001::/48'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '727500', 'domain': 'choisirunmedecin.com', 'dip': '144.76.61.23', 'info': {'Cached': '2017-02-24T10:25:09.688636273Z', 'ASN': 24940, 'CountryCode': 'DE', 'Prefix': '144.76.0.0/16'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '307350', 'domain': 'bestpartyweb.info', 'dip': '104.27.184.20', 'info': {'Cached': '2017-02-24T10:25:14.645460693Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.27.176.0/20'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '499521', 'domain': 'nationalgallery.sg', 'dip': '104.20.3.18', 'info': {'Cached': '2017-02-24T10:25:06.966867911Z', 'ASN': 13335, 'CountryCode': 'US-CA', 'Prefix': '104.20.0.0/20'}}, {'lookupType': 'host', 'lookupAttempts': 1, 'rank': '774975', 'domain': 'granjasantaisabel.com', 'dip': '62.149.128.74', 'info': {'Cached': '2017-02-24T10:25:09.206038319Z', 'ASN': 31034, 'CountryCode': 'IT', 'Prefix': '62.149.128.0/19'}}]

    job_feeder("tests/testdata/webtest_newline.ndjson", spider)
    assert spider.was_shutdown
    assert spider.jobs == expected_jobs
