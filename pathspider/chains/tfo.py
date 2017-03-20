
from pathspider.chains.base import Chain
from pathspider.chains.tcp import tcp_options
from pathspider.chains.tcp import TO_EXPA
from pathspider.chains.tcp import TO_EXPB
from pathspider.chains.tcp import TO_EXP_FASTOPEN
from pathspider.chains.tcp import TO_FASTOPEN

class TFOChain(Chain):

    def _cookie(self, tcp):
        opts = tcp_options(tcp)

        if TO_FASTOPEN in opts:
            return (TO_FASTOPEN, bytes(opts[TO_FASTOPEN]))
        elif TO_EXPA in opts and opts[TO_EXPA][0:2] == bytearray(TO_EXP_FASTOPEN):
            return (TO_EXPA, bytes(opts[TO_EXPA][2:]))
        elif TO_EXPB in opts and opts[TO_EXPB][0:2] == bytearray(TO_EXP_FASTOPEN):
            return (TO_EXPB, tuple(opts[TO_EXPA][2:]))
        else:
            return (None, None)

    def new_flow(self, rec, ip):
        rec['tfo_synkind'] = 0
        rec['tfo_ackkind'] = 0
        rec['tfo_synclen'] = 0
        rec['tfo_ackclen'] = 0
        rec['tfo_seq'] = 0
        rec['tfo_dlen'] = 0
        rec['tfo_ack'] = 0

        return True

    def tcp(self, rec, tcp, rev): # pylint: disable=unused-argument
        # Shortcut non-SYN
        if not tcp.syn_flag:
            return True

        # Check for TFO cookie and data on SYN
        if tcp.syn_flag and not tcp.ack_flag:
            (tfo_kind, tfo_cookie) = self._cookie(tcp)
            if tfo_kind is not None:
                rec['tfo_synkind'] = tfo_kind
                rec['tfo_synclen'] = len(tfo_cookie)
                rec['tfo_seq'] = tcp.seq_nbr
                rec['tfo_dlen'] = len(tcp.data) - tcp.doff*4
                rec['tfo_ack'] = 0

        # Look for ACK of TFO data (and cookie)
        elif tcp.syn_flag and tcp.ack_flag and rec['tfo_synkind']:
            rec['tfo_ack'] = tcp.ack_nbr
            (tfo_kind, tfo_cookie) = self._cookie(tcp)
            if tfo_kind is not None:
                rec['tfo_ackkind'] = tfo_kind
                rec['tfo_ackclen'] = len(tfo_cookie)

        # tell observer to keep going
        return True

    # def test_tfocookie(fn=_tfocookie):
    # TODO: Decide what to do with this test
    #     """
    #     Test the _tfocookie() options parser on a static packet dump test file.
    #     This is used mainly for performance evaluation of the parser for now,
    #     and does not check for correctness.

    #     """
    #     import plt as libtrace

    #     lturi = "pcapfile:testdata/tfocookie.pcap"
    #     trace = libtrace.trace(lturi)
    #     trace.start()
    #     pkt = libtrace.packet()
    #     cookies = 0
    #     nocookies = 0

    #     while trace.read_packet(pkt):
    #         if not pkt.tcp:
    #             continue

    #         # just do the parse
    #         if fn(pkt.tcp):
    #             cookies += 1
    #         else:
    #             nocookies += 1

    #     print("cookies: %u, nocookies: %u" % (cookies, nocookies))
