
def dns_response_setup(rec, _):
    rec['dns_response_valid'] = False

    return True

def dns_response(rec, udp, rev):
    try:
        from pldns import ldns # pylint: disable=E0611
    except ImportError:
        raise RuntimeError("python-libtrace is not installed! Cannot dissect DNS!")

    if rev is True:
        dns = ldns(udp.payload)
        if dns.is_response:
            rec['dns_response_valid'] = True

    return not rec['dns_response_valid']

