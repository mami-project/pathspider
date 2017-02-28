
def ecn_setup(rec, ip):
    fields = ['fwd_ez', 'fwd_eo', 'fwd_ce', 'rev_ez', 'rev_eo', 'rev_ce']
    for field in fields:
        rec[field] = False
    return True

def ecn_code(rec, ip, rev):
    EZ = 0x02
    EO = 0x01
    CE = 0x03

    if ip.traffic_class & CE == EZ:
        rec['rev_ez' if rev else 'fwd_ez'] = True
    if ip.traffic_class & CE == EO:
        rec['rev_eo' if rev else 'fwd_eo'] = True
    if ip.traffic_class & CE == CE:
        rec['rev_ce' if rev else 'fwd_ce'] = True

    return True


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

def _tcpoptions(tcp):
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

def _tfocookie(tcp):
    opts = _tcpoptions(tcp)

    if TO_FASTOPEN in opts:
        return (TO_FASTOPEN, bytes(opts[TO_FASTOPEN]))
    elif TO_EXPA in opts and opts[TO_EXPA][0:2] == bytearray(TO_EXP_FASTOPEN):
        return (TO_EXPA, bytes(opts[TO_EXPA][2:]))
    elif TO_EXPB in opts and opts[TO_EXPB][0:2] == bytearray(TO_EXP_FASTOPEN):
        return (TO_EXPB, tuple(opts[TO_EXPA][2:]))
    else:
        return (None, None)

def _tfosetup(rec, ip):
    rec['tfo_synkind'] = 0
    rec['tfo_ackkind'] = 0
    rec['tfo_synclen'] = 0
    rec['tfo_ackclen'] = 0
    rec['tfo_seq'] = 0
    rec['tfo_dlen'] = 0
    rec['tfo_ack'] = 0

    return True

def _tfopacket(rec, tcp, rev):
    # Shortcut non-SYN
    if not tcp.syn_flag:
        return True

    # Check for TFO cookie and data on SYN
    if tcp.syn_flag and not tcp.ack_flag:
        (tfo_kind, tfo_cookie) = _tfocookie(tcp)
        if tfo_kind is not None:
            rec['tfo_synkind'] = tfo_kind
            rec['tfo_synclen'] = len(tfo_cookie)
            rec['tfo_seq'] = tcp.seq_nbr
            rec['tfo_dlen'] = len(tcp.data) - tcp.doff*4
            rec['tfo_ack'] = 0

    # Look for ACK of TFO data (and cookie)
    elif tcp.syn_flag and tcp.ack_flag and rec['tfo_synkind']:
        rec['tfo_ack'] = tcp.ack_nbr
        (tfo_kind, tfo_cookie) = _tfocookie(tcp)
        if tfo_kind is not None:
            rec['tfo_ackkind'] = tfo_kind
            rec['tfo_ackclen'] = len(tfo_cookie)

    # tell observer to keep going
    return True


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

def _tcpoptions(tcp):
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

def _tfocookie(tcp):
    opts = _tcpoptions(tcp)

    if TO_FASTOPEN in opts:
        return (TO_FASTOPEN, bytes(opts[TO_FASTOPEN]))
    elif TO_EXPA in opts and opts[TO_EXPA][0:2] == bytearray(TO_EXP_FASTOPEN):
        return (TO_EXPA, bytes(opts[TO_EXPA][2:]))
    elif TO_EXPB in opts and opts[TO_EXPB][0:2] == bytearray(TO_EXP_FASTOPEN):
        return (TO_EXPB, tuple(opts[TO_EXPA][2:]))
    else:
        return (None, None)

def _tfosetup(rec, ip):
    rec['tfo_synkind'] = 0
    rec['tfo_ackkind'] = 0
    rec['tfo_synclen'] = 0
    rec['tfo_ackclen'] = 0
    rec['tfo_seq'] = 0
    rec['tfo_dlen'] = 0
    rec['tfo_ack'] = 0

    return True

def _tfopacket(rec, tcp, rev):
    # Shortcut non-SYN
    if not tcp.syn_flag:
        return True

    # Check for TFO cookie and data on SYN
    if tcp.syn_flag and not tcp.ack_flag:
        (tfo_kind, tfo_cookie) = _tfocookie(tcp)
        if tfo_kind is not None:
            rec['tfo_synkind'] = tfo_kind
            rec['tfo_synclen'] = len(tfo_cookie)
            rec['tfo_seq'] = tcp.seq_nbr
            rec['tfo_dlen'] = len(tcp.data) - tcp.doff*4
            rec['tfo_ack'] = 0

    # Look for ACK of TFO data (and cookie)
    elif tcp.syn_flag and tcp.ack_flag and rec['tfo_synkind']:
        rec['tfo_ack'] = tcp.ack_nbr
        (tfo_kind, tfo_cookie) = _tfocookie(tcp)
        if tfo_kind is not None:
            rec['tfo_ackkind'] = tfo_kind
            rec['tfo_ackclen'] = len(tfo_cookie)

    # tell observer to keep going
    return True

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



ICMP_UNREACHABLE = 3

def icmp_setup(rec, ip):
    rec['icmp_unreachable'] = False
    return True

def icmp_unreachable(rec, ip, q, rev):
    if rev and ip.icmp.type == ICMP_UNREACHABLE:
        rec['icmp_unreachable'] = True
    return not rec['icmp_unreachable']
