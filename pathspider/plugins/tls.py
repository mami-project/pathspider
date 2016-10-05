
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
                                                       "host", "rank",
                                                       "config",
                                                       "connstate", "nego"])

test_ssl = ('openssl s_client '
            '-servername {hostname} -connect {ip}:{port} 2>&1 </dev/null | '
            'awk \'{{ if($1 == "Server" && $2 == "public") '
            '{{ print "GOT-TLS"; }} '
            'if($2=="Connection" && $3 == "refused") print "NO-TLS"; '
            'if($1=="gethostbyname" || $0=="connect: No route to host") '
            'print "DNS-FAILURE"}}\'')

test_alpn = ('openssl s_client '
             '-alpn \'h2,http/1.1\' -servername {hostname} -connect {ip}:{port} 2>&1 </dev/null | '
             'awk \'{{if($1 == "ALPN") {{split($0, arr, ":"); '
             'print "ALPN:"arr[2];}} if($2 == "ALPN") print "NO-ALPN"; '
             'if($2=="Connection" && $3 == "refused") print "NO-TLS"; '
             'if($1=="gethostbyname" || $0=="connect: No route to host") '
             'print "DNS-FAILURE"}}\'')

test_npn = ('openssl s_client '
            '-nextprotoneg \'\' -servername {hostname} -connect {ip}:{port} 2>&1 </dev/null')

def execute_test(cmd, job_args):
    return subprocess.run(cmd.format(**job_args),
                          shell=True,
                          timeout=job_args['timeout'],
                          stdout=subprocess.PIPE).stdout.decode('ascii')

class TLS(Spider):
    """
    A PATHspider plugin for TLS testing.
    """

    def config_zero(self):
        pass

    def config_one(self):
        pass

    def connect(self, job, pcs, config):
        job_args = {'hostname': job[2],
                    'ip': job[0],
                    'port': job[1],
                    'timeout': self.args.timeout,
                   }

        connstate = False
        nego = None

        if config == 0:
            try:
                ssl_status = execute_test(test_ssl, job_args).strip()
            except subprocess.TimeoutExpired:
                ssl_status = ""
            if ssl_status == 'GOT_TLS':
                connstate = True
        if config == 1:
            if self.args.test == 'alpn':
                try:
                    alpn_status = execute_test(test_alpn, job_args).strip()
                except subprocess.TimeoutExpired:
                    alpn_status = ""
                if "ALPN" in alpn_status:
                    connstate = True
                    if ":" in alpn_status:
                        nego = alpn_status[6:]
            if self.args.test == 'npn':
                try:
                    npn_status = execute_test(test_npn, job_args).split('\n')
                except subprocess.TimeoutExpired:
                    npn_status = ""
                if len(npn_status) > 0:
                    connstate = True
                    for line in npn_status:
                        if 'advertised' in line:
                            nego = line.split(":")[1].strip()
                            break

        rec = SpiderRecord(job[0], job[1], config, job[2], job[3], config, connstate, nego)
        return rec

    def post_connect(self, job, conn, pcs, config):
        return conn

    def create_observer(self):
        try:
            # this is useless
            return Observer("int:lo",
                            new_flow_chain=[basic_flow],
                            ip4_chain=[basic_count],
                            ip6_chain=[basic_count])
        except:
            print("Observer would not start")
            sys.exit(-1)

    def merge(self, flow, res):
        flow = {"dip": res.ip,
                "dp": res.rport,
                "observed": False,
                "connstate": res.connstate,
                "config": res.config,
                "nego": res.nego,
                "host": res.host,
                "rank": res.rank,
               }
        self.outqueue.put(flow)

    @staticmethod
    def register_args(subparsers):
        parser = subparsers.add_parser('tls', help="Transport Layer Security")
        parser.set_defaults(spider=TLS)
        parser.add_argument("--timeout", default=5, type=int, help="The timeout to use for attempted connections in seconds (Default: 5)")
        parser.add_argument("--test", choices=['alpn', 'npn'], default='alpn', help="Choose to test either ALPN or NPN (Default: ALPN)")

