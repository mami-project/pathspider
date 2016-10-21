
TCP_CWR = 0x80
TCP_ECE = 0x40
TCP_URG = 0x20
TCP_ACK = 0x10
TCP_PSH = 0x08
TCP_RST = 0x04
TCP_SYN = 0x02
TCP_FIN = 0x01

TCP_SA = ( TCP_SYN | TCP_ACK )
TCP_SEC = ( TCP_SYN | TCP_ECE | TCP_CWR )
TCP_SAEC = (TCP_SYN | TCP_ACK | TCP_ECE | TCP_CWR)
TCP_SAE = (TCP_SYN | TCP_ACK | TCP_ECE)

def tcp_setup(rec, ip):
    rec['fwd_syn_flags'] = None
    rec['rev_syn_flags'] = None

    rec['fwd_fin'] = False
    rec['rev_fin'] = False
    rec['fwd_rst'] = False
    rec['rev_rst'] = False

    rec['tcp_connected'] = False

    return True

def tcp_handshake(rec, tcp, rev):
    if rec['tcp_connected']:
        # short-circuit if we're done here
        return True

    if tcp.syn_flag:
        rec['rev_syn_flags' if rev else 'fwd_syn_flags'] = tcp.flags

    # TODO: This test could perhaps be improved upon.
    # This test is intended to catch the completion of the 3WHS.
    if (not rec['tcp_connected'] and rev == 0 and
       rec['fwd_syn_flags'] is not None and
       rec['rev_syn_flags'] is not None and
       tcp.ack_flag):
        rec['tcp_connected'] = True

    return True

def tcp_complete(rec, tcp, rev):
    if tcp.fin_flag and rev:
        rec['rev_fin'] = True
    if tcp.fin_flag and not rev:
        rec['fwd_fin'] = True
    if tcp.rst_flag and rev:
        rec['rev_rst'] = True
    if tcp.rst_flag and not rev:
        rec['fwd_rst'] = True

    return not ((rec['fwd_fin'] and rec['rev_fin']) or
                 rec['fwd_rst'] or rec['rev_rst'])

