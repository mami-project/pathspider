
import sys
import collections
import logging
import subprocess

from pathspider.base import Spider
from pathspider.base import NO_FLOW

from pathspider.observer import Observer
from pathspider.observer import basic_flow
from pathspider.observer import basic_count

SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                       "host", "config",
                                                       "connstate"])

test_ssl = ('timeout {timeout} openssl s_client '
            '-servername {hostname} -connect {ip}:{port}  2>&1 | '
            'awk \'{{ if($1 == "Server" && $2 == "public") '
            '{{ print "GOT-SSL"; }} '
            'if($2=="Connection" && $3 == "refused") print "NO-TLS"; '
            'if($1=="gethostbyname" || $0=="connect: No route to host") '
            'print "DNS-FAILURE"}}\'')

test_alpn = ('timeout {timeout} openssl s_client '
             '-alpn \'h2,http/1.1\' -servername {hostname} -connect {ip}:{port}  2>&1 | '
             'awk \'{{if($1 == "ALPN") {{split($0, arr, ":"); '
             'print "ALPN:"arr[2];}} if($2 == "ALPN") print "NO-ALPN"; '
             'if($2=="Connection" && $3 == "refused") print "NO-TLS"; '
             'if($1=="gethostbyname" || $0=="connect: No route to host") '
             'print "DNS-FAILURE"}}\'')

class TLS(Spider):
    """
    A PATHspider plugin for TLS testing.
    """

    def config_zero(self):
        pass

    def config_one(self):
        pass

    def connect(self, job, pcs, config):
        pass

    def post_connect(self, job, conn, pcs, config):
        job_args = {'hostname': job[2],
                    'ip': job[0],
                    'port': job[1],
                    'timeout': self.args.timeout,
                   }

        if config == 0:
            logging.warning(subprocess.check_output(test_ssl.format(**job_args), shell=True))
            rec = SpiderRecord(job[0], job[1], 0, job[2], config, True)
        if config == 1:
            logging.warning(subprocess.check_output(test_alpn.format(**job_args), shell=True))
            rec = SpiderRecord(job[0], job[1], 0, job[2], config, True)

        return rec

    def create_observer(self):
        try:
            # this is useless
            return Observer(self.libtrace_uri)
        except:
            print("Observer would not start")
            sys.exit(-1)

    def merge(self, flow, res):
        if flow == NO_FLOW:
            flow = {"dip": res.ip,
                    "sp": res.port,
                    "dp": res.rport,
                    "observed": False}
        else:
            flow['observed'] = True

        self.outqueue.put(flow)

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('tls', help="Transport Layer Security")
        parser.set_defaults(spider=TLS)
        parser.add_argument("--timeout", default=5, type=int)

