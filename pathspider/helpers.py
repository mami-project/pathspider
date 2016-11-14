#!/usr/bin/env python3

import socket
import logging

HTTP_SOCKET_TIMEOUT = 10
HTTP_NEWLINE = '\r\n'
HTTP_USER_AGENT = 'firefox'
HTTP_REQUEST = {
    'curl' :    ['GET / HTTP/1.1',
                'Host: {hostname}',
                'User-Agent: curl/7.50.1',
                'Acccept: */*',
                'Connection: keep-alive',
                '',
                ''
                ],
    'firefox' : ['GET / HTTP/1.1',
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

def http_get(sock, host, user_agent=HTTP_USER_AGENT):
    '''
    Performs a http_get request and downloads response.

    :param socket.socket socket: the socket to perform the request over
    :param str host: hostname to place in the 'Host' header field of the request
    :param str user_agent: what user agent to immitate.
        Should be key of `HTTP_REQUEST`
    :rtype: tuple(str, bytes)
    :returns: The tuple (header, content)
    '''

    logger = logging.getLogger('http_get')

    original_timeout = sock.gettimeout()
    sock.settimeout(HTTP_SOCKET_TIMEOUT)

    request = HTTP_NEWLINE.join(HTTP_REQUEST[user_agent])
    request = request.format(hostname = host)

    logger.debug("Sending GET request to {}".format(host))
    try:
        sock.send(bytes(request, 'ASCII'))
    except ConnectionResetError:
        logger.debug("Connection reset while sending request: " + host)
        sock.settimeout(original_timeout)
        return ('', '')
    except socket.timeout:
        logger.debug("Timeout occured while sending request: " + host)
        sock.settimeout(original_timeout)
        return ('', '')

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
            return (header, '')
        except socket.timeout:
            logger.debug("Timeout occured while getting header: " + host)
            sock.settimeout(original_timeout)
            return (header, '')
        if new_char == '':
            logger.debug("Connection closed while getting header: " + host)
            sock.settimeout(original_timeout)
            return (header, '')

        header = header + new_char


    ## SECOND, get the content
    bytes_to_receive = _get_content_length(header)
    logger.debug("Retrieving {} bytes of content from {}".format(
            bytes_to_receive, host))
    if bytes_to_receive == 0:
        return (header, '')

    try:
        content = sock.recv(bytes_to_receive)
    except ConnectionResetError:
        logger.debug("Connection reset while getting content: " + host)
        sock.settimeout(original_timeout)
        return (header, '')
    except socket.timeout:
        logger.debug("Timeout occured while getting content: " + host)
        sock.settimeout(original_timeout)
        return (header, '')

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
