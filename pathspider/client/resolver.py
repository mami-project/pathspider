"""
Ecnspider2: Qofspider-based tool for measuring ECN-linked connectivity
Derived from ECN Spider (c) 2014 Damiano Boppart <hat.guy.repo@gmail.com>

.. moduleauthor:: Elio Gubser <elio.gubser@alumni.ethz.ch>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""

import mplane.client
import threading
import time
import collections
import itertools
import logging

def take(count, iterable):
    """
    Iterate over at most count elements in iterable.
    """
    it = iter(iterable)
    for index in range(0, count):
        if index >= count:
            break
        yield next(it)

class TimeoutException(Exception):
    pass

ResolverResult = collections.namedtuple('ResolverResult', ['ip', 'port', 'hostname'])

class ResolverClient:
    def __init__(self, tls_state, resolver_url, flavor):
        self.url = resolver_url
        self.client = mplane.client.HttpInitiatorClient({}, tls_state)
        self.client.retrieve_capabilities(self.url)
        self.last_updated = 0
        self.lock = threading.RLock()

        self.flavor = flavor

    def _fetch_result(self, token, request_timeout):
        logger = logging.getLogger('resolver')
        time_spent = 0
        while time_spent < request_timeout:
            with self.lock:
                try:
                    # limit polling to once every 5 seconds
                    if self.last_updated + 5 < time.time():
                        # update capabilities information
                        self.client.retrieve_capabilities(self.url)
                        self.last_updated = time.time()
                except:
                    logger.error(str(self.url) + " unreachable. Retrying in 5 seconds")

                # check results
                result = self.client.result_for(token)
                if isinstance(result, mplane.model.Exception):
                    logger.error(result.__repr__())
                    self.client.forget(token)
                    return None
                elif isinstance(result, mplane.model.Receipt):
                    pass
                elif isinstance(result, mplane.model.Result):
                    addrs = list(result.schema_dict_iterator())
                    self.client.forget(token)
                    return addrs
                else:
                    # other result, just print it out
                    logger.info(result)

            time.sleep(5)
            time_spent += 5

        raise TimeoutException("Could not complete address retrieval within timeout period.")

    def request(self, count, ipv='ip4', when = 'now ... future', request_timeout = 30):
        raise NotImplementedError("You have to implement this function in your subclass of ResolverClient.")

class BtDhtResolverClient(ResolverClient):
    def __init__(self, tls_state, resolver_url):
        super(BtDhtResolverClient, self).__init__(tls_state, resolver_url, 'tcp')

    def request(self, count, ipv='ip4', when = 'now ... future', request_timeout = 300):
        logger = logging.getLogger('resolver')
        logger.debug("Requesting {} addresses using BitTorrent DHT...".format(count))
        token = None
        with self.lock:
            label = 'btdhtresolver-'+ipv
            try:
                spec = self.client.invoke_capability(label, when, { "btdhtresolver.count": count })
                token = spec.get_token()
            except KeyError as e:
                logger.error("Specified URL does not support '"+label+"' capability.")
                raise e

        if token is None:
            raise ValueError("Could not acquire request token.")

        addrs = [ResolverResult(row['destination.'+ipv], row['destination.port'], None) for row in self._fetch_result(token, request_timeout)]

        # ensure ip-uniqueness
        addrs_unique = []
        ipset = set()
        for addr in addrs:
            if addr[0] not in ipset:
                ipset.add(addr[0])
                addrs_unique.append(addr)

        logger.debug("Received {} unique addresses.".format(count))
        return addrs_unique

class WebResolverClient(ResolverClient):
    def __init__(self, tls_state, resolver_url, urls = None):
        super(WebResolverClient, self).__init__(tls_state, resolver_url, 'http')
        self.lock = threading.RLock()
        self.queued = collections.deque()
        if urls is not None:
            self.queued.extend(urls)

    def extend(self, urls):
        with self.lock:
            self.queued.extend(urls)

    def __len__(self):
        return len(self.queued)

    def request(self, count, ipv='ip4', when = 'now ... future', request_timeout = 30):
        logger = logging.getLogger('resolver')
        logger.debug("Requesting {} addresses using the web resolver...".format(count))
        token = None
        with self.lock:
            label = 'webresolver-'+ipv
            try:
                hosts = list(take(count, self.queued))
                spec = self.client.invoke_capability(label, when, { "ecnspider.hostname": hosts, 'destination.port': itertools.repeat(80, len(hosts)) })
                token = spec.get_token()
            except KeyError as e:
                logger.error("Specified URL does not support '"+label+"' capability.")
                raise e

        if token is None:
            raise ValueError("Could not acquire request token.")

        logger.debug("Received {} unique addresses.".format(count))

        return [ResolverResult(row['destination.'+ipv], row['destination.port'], row['ecnspider.hostname']) for row in self._fetch_result(token, request_timeout)]

class IPListDummyResolver:
    def __init__(self, addrs = ()):
        self.addrs = collections.deque([ResolverResult(ip, port, None) for ip, port in addrs])
        self.flavor = 'tcp'

    def __len__(self):
        return len(self.addrs)

    def request(self, count, ipv='ip4', when = 'now ... future', request_timeout = 30):
        taken = []
        try:
            for _ in range(0, count):
                taken.append(self.addrs.popleft())
        except IndexError:
            pass

        return taken