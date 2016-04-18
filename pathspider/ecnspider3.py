
import sys
import logging
import subprocess

import http.client
import collections

from base import Spider
from observer import Observer

Job = collections.namedtuple("Job", ["ip", "host", "rport"])
Connection = collections.namedtuple("Connection", ["client", "port", "state"])
SpiderRecord = collections.namedtuple("SpiderRecord",
            ["ip", "host", "port", "rport", "ecnstate", "connstate", "httpstatus",
                        "userval"])

CONN_OK = 0
CONN_FAILED = 1
CONN_TIMEOUT = 2

USER_AGENT = "pathspider"

class ECNSpider(Spider):

    def __init__(self, worker_count, libtrace_uri, check_interrupt=None):
        super().__init__(worker_count=worker_count,
                         libtrace_uri=libtrace_uri,
                         check_interrupt=check_interrupt)
        self.tos = None # set by configurator
        self.conn_timeout = 10

    def config_zero(self):
        logger = logging.getLogger('ecnspider3')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Configurator disabled ECN")

    def config_one(self):
        logger = logging.getLogger('ecnspider3')
        subprocess.check_call(['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Configurator enabled ECN")

    def connect(self, job, pcs, config):
        client = http.client.HTTPConnection(str(job.ip), timeout=self.conn_timeout)
        client.auto_open = 0
        try:
            client.connect()
        except socket.timeout:
            return Connection(None, None, CONN_TIMEOUT)
        except OSError as e:
            return Connection(None, None, CONN_FAILED)
        else:
            return Connection(client, client.sock.getsockname()[1], CONN_OK)

    def post_connect(self, job, conn, pcs, config):
        if conn.state == CONN_OK:
            headers = {'User-Agent': USER_AGENT,
                       'Connection': 'close',
                       'Host': job.host}
            try:
                conn.client.request('GET', '/', headers=headers)
                res = conn.client.getresponse()
                conn.client.close()

                return SpiderRecord(job.ip, job.host, conn.port, job.rport, config, True, res.status, None)
            except:
                return SpiderRecord(job.ip, job.host, conn.port, job.rport, config, True, 0, None)
            finally:
                conn.client.close()
        else:
            return SpiderRecord(job.ip, job.host, 0, job.rport, config, False, 0, None)

    def create_observer(self):
        logger = logging.getLogger('ecnspider3')
        logger.info("Creating observer")
        try:
            return Observer(self.libtrace_uri)
        except:
            logger.error("Observer not cooperating, abandon ship")
            sys.exit()

    def merge(self, flow, res):
        logger = logging.getLogger('ecnspider3')
        logger.info("Merging " + str(flow) + " with " + str(res))

logging.getLogger('ecnspider3').setLevel(logging.DEBUG)
logging.getLogger('pathspider').setLevel(logging.DEBUG)
ecnspider = ECNSpider(2, "int:enp0s25")
ecnspider.add_job(Job("139.133.210.32", "galactica.erg.abdn.ac.uk", "80"))
ecnspider.add_job(Job("139.133.210.32", "galactica.erg.abdn.ac.uk", "80"))
ecnspider.add_job(Job("139.133.210.32", "galactica.erg.abdn.ac.uk", "80"))
#ecnspider.add_job(Job("2001:630:241:210:569f:35ff:fe0a:116a", "galactica.erg.abdn.ac.uk", "80"))
ecnspider.run()

while ecnspider.running:
    pass

