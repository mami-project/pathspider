
from pathspider.observer.base import Chain

TCP_CWR = 0x80
TCP_ECE = 0x40
TCP_URG = 0x20
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_RST = 0x04
TCP_SYN = 0x02
TCP_FIN = 0x01

TCP_SA = (TCP_SYN | TCP_ACK)
TCP_SEC = (TCP_SYN | TCP_ECE | TCP_CWR)
TCP_SAEC = (TCP_SYN | TCP_ACK | TCP_ECE | TCP_CWR)
TCP_SAE = (TCP_SYN | TCP_ACK | TCP_ECE)

TO_EOL = 0
TO_NOP = 1
TO_MSS = 2
TO_WS = 3
TO_SACKOK = 4
TO_SACK = 5
TO_TS = 8
TO_MPTCP = 30
TO_FASTOPEN = 34
TO_EXPA = 254
TO_EXPB = 255
TO_EXP_FASTOPEN = (0xF9, 0x89)

def tcp_options(tcp):
    """
    Given a TCP header, make TCP options available
    according to the interface we've designed for python-libtrace

    """
    optbytes = tcp.data[20:tcp.doff*4]
    opthash = {}

    # shortcut empty options
    if len(optbytes) == 0:
        return opthash

    # parse options in place
    cp = 0
    ncp = 0

    while cp < len(optbytes):
        # skip NOP
        if optbytes[cp] == TO_NOP:
            cp += 1
            continue
        # die on EOL
        if optbytes[cp] == TO_EOL:
            break

        # parse options length
        ncp = cp + optbytes[cp+1]

        # copy options data into hash
        # FIXME doesn't handle multiples
        opthash[optbytes[cp]] = optbytes[cp+2:ncp]

        # advance
        cp = ncp

    return opthash

class TCPChain(Chain):

    def new_flow(self, rec, ip): # pylint: disable=W0613
        rec['tcp_synflags_fwd'] = None
        rec['tcp_synflags_rev'] = None

        rec['tcp_fin_fwd'] = False
        rec['tcp_fin_rev'] = False
        rec['tcp_rst_fwd'] = False
        rec['tcp_rst_rev'] = False

        rec['tcp_connected'] = False

        return True

    def tcp(self, rec, tcp, rev):
        if tcp.syn_flag:
            rec['tcp_synflags_rev' if rev else 'tcp_synflags_fwd'] = tcp.flags

        # This test is intended to catch the completion of the 3WHS.
        if (not rec['tcp_connected'] and rev == 0 and
                rec['tcp_synflags_fwd'] & TCP_SYN == TCP_SYN and
                rec['tcp_synflags_rev'] & TCP_SA == TCP_SA and
                tcp.ack_flag):
            rec['tcp_connected'] = True

        if tcp.fin_flag and rev:
            rec['tcp_fin_fwd'] = True
        if tcp.fin_flag and not rev:
            rec['tcp_fin_rev'] = True
        if tcp.rst_flag and rev:
            rec['tcp_rst_rev'] = True
        if tcp.rst_flag and not rev:
            rec['tcp_rst_fwd'] = True

        return not ((rec['tcp_fin_fwd'] and rec['tcp_fin_rev']) or
                    rec['tcp_rst_fwd'] or rec['tcp_rst_rev'])
