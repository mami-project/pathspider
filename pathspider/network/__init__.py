
from io import BytesIO
import json

import pycurl
from pyroute2 import IPDB # pylint: disable=no-name-in-module

def interface_up(ifname):
    with IPDB() as ipdb:
        for i in set(ipdb.interfaces.values()):
            if i.ifname == ifname and i.operstate == 'UP':
                return True
        return False

def ipv4_address(ifname):
    with IPDB() as ipdb:
        addrset = [x[0] for x in ipdb.interfaces[ifname].ipaddr if '.' in x[0]]
        if len(addrset) > 0:
            # Should return the first IPv4 address of the interface...if there are any
            return addrset[0]

def ipv6_address(ifname):
    with IPDB() as ipdb:
        addrset = [x[0] for x in ipdb.interfaces[ifname].ipaddr
                   if ':' in x[0] and not x[0].startswith('fe')]
        if len(addrset) > 0:
            # Should return the first IPv6 address of the interface...if there are any
            return addrset[0]

def ipv4_address_public(ifname):
    c = pycurl.Curl()
    body = BytesIO()
    c.setopt(c.URL, "https://stat.ripe.net/data/whats-my-ip/data.json")
    c.setopt(c.INTERFACE, ifname)
    c.setopt(c.WRITEDATA, body)
    c.setopt(c.IPRESOLVE, c.IPRESOLVE_V4)
    c.perform()
    return json.loads((body.getvalue()).decode('utf-8'))['data']['ip']

def ipv6_address_public(ifname):
    try:
        c = pycurl.Curl()
        body = BytesIO()
        c.setopt(c.URL, "https://stat.ripe.net/data/whats-my-ip/data.json")
        c.setopt(c.INTERFACE, ifname)
        c.setopt(c.WRITEDATA, body)
        c.setopt(c.IPRESOLVE, c.IPRESOLVE_V6)
        c.perform()
        return json.loads((body.getvalue()).decode('utf-8'))['data']['ip']
    except pycurl.error:
        return "::"

def ipv4_asn(ifname):
    c = pycurl.Curl()
    body = BytesIO()
    c.setopt(c.URL, "https://stat.ripe.net/data/prefix-overview/data.json?resource={}"
             .format(ipv4_address_public(ifname)))
    c.setopt(c.INTERFACE, ifname)
    c.setopt(c.WRITEDATA, body)
    c.perform()
    asns = json.loads((body.getvalue()).decode('utf-8'))['data']['asns']
    if len(asns) == 1:
        return asns[0]['asn']
    else:
        return None

def ipv6_asn(ifname):
    try:
        c = pycurl.Curl()
        body = BytesIO()
        c.setopt(c.URL, "https://stat.ripe.net/data/prefix-overview/data.json?resource={}"
                 .format(ipv6_address_public(ifname)))
        c.setopt(c.INTERFACE, ifname)
        c.setopt(c.WRITEDATA, body)
        c.perform()
        asns = json.loads((body.getvalue()).decode('utf-8'))['data']['asns']
        if len(asns) == 1:
            return asns[0]['asn']
        else:
            return None
    except pycurl.error:
        return None
