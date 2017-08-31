
from io import BytesIO

import pycurl

from pathspider.base import CONN_OK
from pathspider.base import CONN_FAILED

def connect_http(source, job, conn_timeout, curlopts=None, curlinfos=None):
    """
    This helper function will perform a TCP connection. It will not perform
    any special action in the event that this is the experimental flow,
    but can be customised on a per-call basis through the curlopts argument.
    """

    c = pycurl.Curl()

    if curlopts is None:
        curlopts = {}

    if source is not None:
        if ":" in job['dip']:
            curlopts[pycurl.INTERFACE] = source[1]
        else:
            curlopts[pycurl.INTERFACE] = source[0]

    if ':' in job['dip']:
        ipString = '[' + job['dip'] + ']'
    else:
        ipString = job['dip']

    if pycurl.URL not in curlopts:
        if 'domain' in job:
            url = "http://" + job['domain'] + ":" + str(job['dp']) + "/"
        else:
            url = "http://" + ipString + ":" + str(job['dp']) + "/"
    else:
        curlopts[pycurl.URL] = url

    if pycurl.USERAGENT not in curlopts:
        useragent = "PATHspider (https://pathspider.net/)"
        curlopts[pycurl.USERAGENT] = useragent

    curlopts[pycurl.TIMEOUT] = conn_timeout

    curlopts[pycurl.CONNECT_TO] = ["::{}:{}".format(ipString, job['dp'])]

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
        info = {}
        if curlinfos is not None:
            for curlinfo in curlinfos:
                info[curlinfo] = c.getinfo(curlinfo)
        c.close()
        return {
            'sp': sp,
            'spdr_state': CONN_OK,
            'http_response_code': code,
            'http_response_header': header.getvalue(),
            'http_response_body': body.getvalue(),
            'http_info': info,
        }
    except pycurl.error: # TODO: Catch timeout seperately
        return {'spdr_state': CONN_FAILED, 'sp': 0}

def connect_https(source, job, conn_timeout, curlopts=None, curlinfos=None):
    if curlopts is None:
        curlopts = {}

    if ':' in job['dip']:
        ipString = '[' + job['dip'] + ']'
    else:
        ipString = job['dip']

    if pycurl.URL not in curlopts:
        if 'domain' in job:
            url = "http://" + job['domain'] + ":" + str(job['dp']) + "/"
        else:
            url = "http://" + ipString + ":" + str(job['dp']) + "/"
    else:
        curlopts[pycurl.URL] = url

    if pycurl.SSL_VERIFYHOST not in curlopts:
        curlopts[pycurl.SSL_VERIFYHOST] = 0

    if pycurl.SSL_VERIFYPEER not in curlopts:
        curlopts[pycurl.SSL_VERIFYPEER] = 0

    return connect_http(source, job, conn_timeout, curlopts, curlinfos)
