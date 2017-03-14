
class DNSChain:

    def new_flow(self, rec, ip):
        rec['dns_response_valid'] = False

        return True

    def tcp(self, rec, tcp, rev):
        return self._dns_response(rec, tcp, rev)

    def udp(self, rec, udp, rev):
        return self._dns_response(rec, udp, rev)

    def _dns_response(self, rec, l4, rev):
        try:
            from pldns import ldns # pylint: disable=E0611
        except ImportError:
            raise RuntimeError("python-libtrace is not installed! "
                               "Cannot dissect DNS!")

        if rev is True:
            try:
                dns = ldns(l4.payload)
            except ValueError:
                pass # Probably not a DNS payload
            else:
                if dns.is_response:
                    rec['dns_response_valid'] = True

        return not rec['dns_response_valid']

