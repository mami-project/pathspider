
from pathspider.chains.base import Chain

class BasicChain(Chain):

    def _extract_ports(self, ip):
        if ip.udp:
            return (ip.udp.src_port, ip.udp.dst_port)
        elif ip.tcp:
            return (ip.tcp.src_port, ip.tcp.dst_port)
        else:
            return (None, None)

    def new_flow(self, rec, ip):
        """
        New flow function that sets up basic flow information
        """

        # Extract addresses and ports
        (rec['sip'], rec['dip'], rec['proto']) = (str(ip.src_prefix), str(ip.dst_prefix), ip.proto)
        (rec['sp'], rec['dp']) = self._extract_ports(ip)

        # Initialize counters
        rec['pkt_fwd'] = 0
        rec['pkt_rev'] = 0
        rec['oct_fwd'] = 0
        rec['oct_rev'] = 0

        # we want to keep this flow
        return True

    def ip4(self, rec, ip, rev):
        return self._basic_count(rec, ip, rev)

    def ip6(self, rec, ip, rev):
        return self._basic_count(rec, ip, rev)

    def _basic_count(self, rec, ip, rev):
        """
        Packet function that counts packets and octets per flow
        """

        if rev:
            rec["pkt_rev"] += 1
            rec["oct_rev"] += ip.size
        else:
            rec["pkt_fwd"] += 1
            rec["oct_fwd"] += ip.size

        return True
