
ICMP_UNREACHABLE = 3

def icmp_setup(rec, _):
    rec['icmp_unreachable'] = False
    return True

def icmp_unreachable(rec, ip, _, rev):
    if rev and ip.icmp.type == ICMP_UNREACHABLE:
        rec['icmp_unreachable'] = True
    return not rec['icmp_unreachable']
