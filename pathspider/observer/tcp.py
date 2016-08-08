
def tcp_setup(rec, ip):
    rec['fwd_fin'] = False
    rec['fwd_rst'] = False
    rec['rev_fin'] = False
    rec['rev_rst'] = False

    return True

def tcp_complete(rec, tcp, rev): # pylint: disable=W0612,W0613
    if tcp.fin_flag and rev:
        rec['rev_fin'] = True
    if tcp.fin_flag and not rev:
        rec['fwd_fin'] = True
    if tcp.rst_flag and rev:
        rec['rev_rst'] = True
    if tcp.rst_flag and not rev:
        rec['fwd_rst'] = True

    return not ( ( rec['fwd_fin'] and rec['rev_fin'] ) or
                 rec['fwd_rst'] or rec['rev_rst'] )

