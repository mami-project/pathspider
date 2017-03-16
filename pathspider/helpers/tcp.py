
import socket
from io import BytesIO

import pycurl

from scapy.all import RandShort

from pathspider.base import CONN_OK
from pathspider.base import CONN_TIMEOUT
from pathspider.base import CONN_FAILED

def connect_tcp(source, job, conn_timeout, sockopts=None):
    """
    This helper function will perform a TCP connection. It will not perform
    any special action in the event that this is the experimental flow,
    it only performs a TCP connection.
    """

    if sockopts is None:
        sockopts = []

    if not isinstance(conn_timeout, int):
        raise RuntimeError("Plugin did not set TCP connect conn_timeout.")

    try:
        if ":" in job['dip']:
            sock = socket.socket(socket.AF_INET6)
            sock.bind((source[1], 0))
        else:
            sock = socket.socket(socket.AF_INET)
            sock.bind((source[0], 0))

        for o in sockopts:
            sock.setsockopt(*o)

        sock.settimeout(conn_timeout)
        sock.connect((job['dip'], job['dp']))

        sp = sock.getsockname()[1]

        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        return {'sp': sp, 'spdr_state': CONN_OK}
    except TimeoutError:
        return {'sp': sock.getsockname()[1], 'spdr_state': CONN_TIMEOUT}
    except TypeError: # Caused by not having a v4/v6 address when trying to bind
        return {'sp': 0, 'spdr_state': CONN_FAILED}
    except OSError:
        return {'sp': 0, 'spdr_state': CONN_FAILED}

def connect_http(source, job, conn_timeout, curlopts=None):
    """
    This helper function will perform a TCP connection. It will not perform
    any special action in the event that this is the experimental flow,
    but can be customised on a per-call basis through the curlopts argument.
    """

    c = pycurl.Curl()

    if curlopts is None:
        curlopts = {}

    if ":" in job['dip']:
        curlopts[pycurl.INTERFACE] = source[1]
    else:
        curlopts[pycurl.INTERFACE] = source[0]
    curlopts[pycurl.LOCALPORT] = int(RandShort())

    if pycurl.URL not in curlopts:
        url = "http://" + job['dip'] + ":" + str(job['dp']) + "/"
        curlopts[pycurl.URL] = url

    if pycurl.USERAGENT not in curlopts:
        useragent = "PATHspider (https://pathspider.net/)"
        curlopts[pycurl.USERAGENT] = useragent

    if 'domain' in job:
        curlopts[pycurl.HTTPHEADER] = ["Host: " + job['domain']]

    curlopts[pycurl.TIMEOUT] = conn_timeout

    header = BytesIO()
    curlopts[pycurl.HEADERFUNCTION] = header.write
    body = BytesIO()
    curlopts[pycurl.WRITEDATA] = body

    curlopts[pycurl.FRESH_CONNECT] = 1
    curlopts[pycurl.FORBID_REUSE] = 1

    for o in curlopts:
        try:
            c.setopt(o, curlopts[o])
        except TypeError:
            return {'spdr_state': CONN_FAILED, 'sp': 0}

    try:
        c.perform()
        sp = c.getinfo(pycurl.LOCAL_PORT)
        code = c.getinfo(pycurl.RESPONSE_CODE)
        c.close()
        return {
            'sp': sp,
            'spdr_state': CONN_OK,
            'http_response_code': code,
            'http_response_header': header.getvalue().decode('utf-8'),
            'http_response_body': body.getvalue().decode('utf-8'),
        }
    except OSError:
        import traceback
        print(o)
        traceback.print_exc()
        return {'spdr_state': CONN_FAILED, 'sp': 0}
