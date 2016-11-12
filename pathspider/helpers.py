#!/usr/bin/env python3

import socket
import logging

HTTP_REQUEST = \
'GET / HTTP/1.1\r\n' \
'Host: {hostname}\r\n' \
'Connection: keep-alive\r\n' \
'User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36\r\n' \
'Accept-Encoding: gzip, deflate, sdch6\r\n' \
'\r\n' \
'\r\n' \

HTTP_REQUEST = \
'GET / HTTP/1.1\r\n' \
'Host: {hostname}\r\n' \
'User-Agent: curl/7.50.1\r\n' \
'Acccept: */*\r\n' \
'Connection: keep-alive\r\n' \
'\r\n' \

HTTP_REQUEST = \
'GET / HTTP/1.1\r\n' \
'Host: {hostname}\r\n' \
'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0\r\n' \
'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' \
'Accept-Language: en-US,en;q=0.5\r\n' \
'Accept-Encoding: gzip, deflate\r\n' \
'Connection: keep-alive\r\n' \
'Cache-Control: max-age=0\r\n' \
'\r\n\r\n' \

def _detect_end_of_header(response):
    if response.endswith('\n'*2): return True
    if response.endswith('\r\n'*2): return True
    return False

def _get_content_length(header):
    header = header.splitlines()
    for line in header:
        line = line.lower().strip()
        if 'content-length' in line:
            name, content = line.split(':')
            return int(content.strip())

    return 0

def http_get(sock, host):
    sock.settimeout(10)
    logger = logging.getLogger('http_get')
    request = HTTP_REQUEST.format(hostname = host)

    try:
        sock.send(bytes(request, 'ASCII'))
    except ConnectionResetError:
        logger.debug("Connection reset while sending request: " + host)
        return ('', '')
    except socket.timeout:
        logger.debug("Timeout occured while sending request: " + host)
        return ('', '')

    ## FIRST, get the header
    header = ''
    counter = 0
    while not _detect_end_of_header(header):
        counter = counter + 1
        #logger.info('Looping! {}'.format(counter))
        try:
            new_char =  sock.recv(1).decode('ASCII')
        except ConnectionResetError:
            logger.debug("Connection reset while getting header: " + host)
            return (header, '')
        except socket.timeout:
            logger.debug("Timeout occured while getting header: " + host)
            print(header)
            return (header, '')
        if new_char == '':
            logger.debug("Connection closed while getting header: " + host)
            return (header, '')

        header = header + new_char

    ## SECOND, get the content
    bytes_to_receive = _get_content_length(header)

    if bytes_to_receive == 0:
        return (header, '')

    try:
        content = sock.recv(bytes_to_receive)
    except ConnectionResetError:
        logger.debug("Connection reset while getting content: " + host)
        return (header, '')
    except socket.timeout:
        logger.debug("Timeout occured while getting content: " + host)
        return (header, '')

    return (header, content)

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
