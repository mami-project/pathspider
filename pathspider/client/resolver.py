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
import logging

from . import BaseClientApi

def take(count, iterable):
    """
    Iterate over at most count elements in iterable.
    """
    it = iter(iterable)
    for index in range(0, count):
        if index >= count:
            break
        yield next(it)

class ResolverApi(BaseClientApi):
    def __init__(self, client, ipv):
        assert(ipv == 'ip4' or ipv == 'ip6')
        self.client = client
        self.ipv = ipv
        self.pending_tokens = {}

        self.logger = logging.getLogger("agent.resolver.btdht")

    def _invoke(self, label, params, result_sink):
        try:
            spec = self.client.invoke_capability(label, "now ... future", params)
            token = spec.get_token()
            self.pending_tokens[token] = (label, result_sink)
            return token
        except KeyError as e:
            self.logger.error("Probe does not support '"+label+"' capability.")
            return False

    def resolve_btdht(self, count, result_sink):
        return self._invoke('btdhtresolver-'+self.ipv, { "btdhtresolver.count": count }, result_sink)

    def resolve_web(self, hostnames, result_sink):
        return self._invoke('webresolver-'+self.ipv, { "ecnspider.hostname": hostnames }, result_sink)

    def _process_result(self, label, token, result_sink, result):
        if label == 'btdhtresolver-ip4' or label == 'btdhtresolver-ip6':
            addrs = [(str(row['destination.'+self.ipv]), row['destination.port'], str(row['destination.'+self.ipv])) for row in result.schema_dict_iterator()]
            result_sink(label=label, token=token, result=addrs)
        elif label == 'webresolver-ip4' or label == 'webresolver-ip6':
            addrs = [(str(row['destination.'+self.ipv]), 80, str(row['ecnspider.hostname'])) for row in result.schema_dict_iterator()]
            result_sink(label=label, token=token, result=addrs)

    def process(self):
        tokens_to_remove = set()
        for token, (label, result_sink) in self.pending_tokens.items():
            # iterate over pending
            try:
                result = self.client.result_for(token)
            except KeyError:
                tokens_to_remove.add(token)
                result_sink(label=label, token=token, error='token_not_found')
                self.logger.exception("Token not found")
            else:
                if isinstance(result, mplane.model.Exception):
                    tokens_to_remove.add(token)
                    result_sink(label=label, token=token, error=result)
                elif isinstance(result, mplane.model.Receipt):
                    pass
                elif isinstance(result, mplane.model.Result):
                    tokens_to_remove.add(token)
                    self._process_result(label, token, result_sink, result)
                    self.client.forget(token)
                else:
                    # other result, just print it out
                    print(result)

        for token in tokens_to_remove:
            del self.pending_tokens[token]