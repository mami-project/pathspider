import socket

import pathspider.base
from pathspider.base import PluggableSpider
from pathspider.base import CONN_DISCARD
from pathspider.desync import DesynchronizedSpider


class DNSResolv(DesynchronizedSpider, PluggableSpider):

    name = "dnsresolv"
    description = "Simple Input List DNS Resolver"
    version = pathspider.base.__version__
    chains = [] # Use the dummy observer

    def resolv_host(self, job, config): # pylint: disable=unused-argument
        if 'domain' not in job or job['domain'] is None:
            return {'spdr_state': CONN_DISCARD} # Always discard
        try:
            ips = set([str(i[4][0]) for i in socket.getaddrinfo(job['domain'], 80)])
        except socket.gaierror:
            return {'spdr_state': CONN_DISCARD} # Always discard
        for ip in ips:
            res = job.copy()
            res['dip'] = ip
            self.outqueue.put(res)
        return {'spdr_state': CONN_DISCARD} # Always discard

    connections = [resolv_host]
