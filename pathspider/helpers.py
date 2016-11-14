#!/usr/bin/env python3

import socket
import logging

HTTP_SOCKET_TIMEOUT = 10
HTTP_NEWLINE = '\r\n'
HTTP_USER_AGENT = 'firefox'
HTTP_REQUEST = {
    'curl' :    ['{method} / HTTP/1.1',
                'Host: {hostname}',
                'User-Agent: curl/7.50.1',
                'Acccept: */*',
                'Connection: keep-alive',
                '',
                ''
                ],
    'firefox' : ['{method} / HTTP/1.1',
                'Host: {hostname}',
                'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0)'\
                'Gecko/20100101 Firefox/45.0',
                'Accept: text/html,application/xhtml+xml,application/xml;'\
                'q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.5',
                'Accept-Encoding: gzip, deflate',
                'Connection: keep-alive',
                'Cache-Control: max-age=0',
                '',
                ''
                ]
}

def _detect_end_of_header(response):
    '''
    Returns true if the end of the header section of a HTTP resonse is detected

    Checks if `response` ends in two consecutive newlines.
    :param str response: the (partial) response from the server
    :rtype: bool
    :returns: true is the `response` ends in two consecutive newlines.
    '''
    if response.endswith('\n'*2): return True
    if response.endswith('\r\n'*2): return True
    return False

def _get_content_length(header):
    '''
    Returns the value of the 'Content-Length' field in a HTTP header.

    returns 0 if the 'Content-Lenght' field was not present or could not
    be decoded.
    :param str header: a http header
    :rtype: int
    :returns: the value of the 'Content-Lenght' field
    '''

    logger=logging.getLogger('http_get')
    header = header.splitlines()
    for line in header:
        line = line.lower().strip()
        if 'content-length:' in line:
            name, content = line.split(':')
            try:
                return int(content.strip())
            except ValueError:
                logger.debug(
                    "Not able to parse content-length: {}".format(header))
                break
    return 0

def http_request(sock, host, method = 'GET', user_agent=HTTP_USER_AGENT):
    '''
    Performs a http GET of HEAD request and downloads response.

    This functions assumes the socket to have an open connection.
    If the request uses the HEAD method, the content field of the return tuple
    will be an empty bytes object.

    :param socket.socket socket: the socket to perform the request over
    :param str host: hostname to place in the 'Host' header field of the request
    :param str user_agent: what user agent to immitate.
        Should be key of `HTTP_REQUEST`
    :param str method: type of request to make. Should be 'GET' or 'HEAD'
    :rtype: tuple(str, bytes)
    :returns: The tuple (header, content)
    '''

    assert method in ('GET', 'HEAD')

    logger = logging.getLogger('http_request')

    original_timeout = sock.gettimeout()
    sock.settimeout(HTTP_SOCKET_TIMEOUT)

    request = HTTP_NEWLINE.join(HTTP_REQUEST[user_agent])
    request = request.format(method = method, hostname = host)

    logger.debug("Sending GET request to {}".format(host))
    try:
        sock.send(bytes(request, 'ASCII'))
    except ConnectionResetError:
        logger.debug("Connection reset while sending request: " + host)
        sock.settimeout(original_timeout)
        return ('', bytes())
    except socket.timeout:
        logger.debug("Timeout occured while sending request: " + host)
        sock.settimeout(original_timeout)
        return ('', bytes())

    ## FIRST, get the header
    header = ''
    counter = 0

    logger.debug("Retrieving header from {}".format(host))
    while not _detect_end_of_header(header):
        counter = counter + 1
        #logger.info('Looping! {}'.format(counter))
        try:
            new_char =  sock.recv(1).decode('ASCII')
        except ConnectionResetError:
            logger.debug("Connection reset while getting header: " + host)
            sock.settimeout(original_timeout)
            return (header, bytes())
        except socket.timeout:
            logger.debug("Timeout occured while getting header: " + host)
            sock.settimeout(original_timeout)
            return (header, bytes())
        if new_char == '':
            logger.debug("Connection closed while getting header: " + host)
            sock.settimeout(original_timeout)
            return (header, bytes())

        header = header + new_char

    # The HEAD method does not need to fetch the content.
    if method == 'HEAD':
        logger.debug('Done with HEAD request to {}, returning'.format(host))
        return (header, bytes())

    ## SECOND, get the content
    bytes_to_receive = _get_content_length(header)
    logger.debug("Retrieving {} bytes of content from {}".format(
            bytes_to_receive, host))
    if bytes_to_receive == 0:
        return (header, bytes())

    try:
        content = sock.recv(bytes_to_receive)
    except ConnectionResetError:
        logger.debug("Connection reset while getting content: " + host)
        sock.settimeout(original_timeout)
        return (header, bytes())
    except socket.timeout:
        logger.debug("Timeout occured while getting content: " + host)
        sock.settimeout(original_timeout)
        return (header, bytes())

    logger.debug("Done with retrieving content from {}".format(host))
    sock.settimeout(original_timeout)
    return (header, content)

# Just some debugging stuff, you can probably ignore this.
if __name__ == "__main__":

    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    HOST = "www.wordpress.com"
    PORT = 80

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))

    header, content = http_get(s, HOST)

    print(header)
    print('--------------------')
    print(content)
