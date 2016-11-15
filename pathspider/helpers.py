#!/usr/bin/env python3

import socket
import logging

class Http_Request():
    """
    Class to perform a http GET of HEAD request and download the response.

    Note that many of the functions should be called in a particular order.
    Namely: `send_request()` --> `receive_header()` --> `receive_content()`
    `run()` is a wrapper that will perform all three of these functions.
    """

    STATE_INIT = 1
    STATE_REQUEST_MADE = 2
    STATE_RETRIEVED_HEADER = 3
    STATE_RETRIEVED_CONTENT = 4
    STATE_ERROR = 5

    SOCKET_TIMEOUT = 10
    HTTP_NEWLINE = '\r\n'
    DEFAULT_USER_AGENT = 'firefox'
    HTTP_REQUEST_PROTOTYPE = {
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

    def __init__(self, sock, host, method = None, user_agent = None):
        """
        Create new class instance to perform a HTTP GET or HEAD request.

        Each class instance can only be used to perform one HTTP GET or HEAD
        request.

        :param socket.socket socket: the socket to perform the request over
        :param str host: hostname to place in the 'Host' header field of the request
        :param str user_agent: what user agent to immitate.
            Should be key of `Http_Request.HTTP_REQUEST`
        :param str method: type of request to make. Should be 'GET' or 'HEAD'
        """

        self.sock = sock
        self.host = host
        self.method = method if method else 'GET'
        self.user_agent = user_agent if user_agent else self.DEFAULT_USER_AGENT

        self.logger = logging.getLogger('http_request')
        self.state = self.STATE_INIT
        self.header = ''
        self.content = bytes()

        assert self.method in ('GET', 'HEAD')
        assert self.user_agent in self.HTTP_REQUEST_PROTOTYPE

    def run(self):
        """
        Perform the HTTP request and retrieve the result.

        Will return a tuple containing the response header, content and
        success status.

        :rtype: tuple(str, bytes, bool)
        :returns: the tuple (header, content, success)
        """

        if not self.send_request():
            return ('', bytes(), False)

        if self.receive_header()[2] == False:
            return ('', bytes(), False)

        if self.method == 'GET':
            if self.receive_content()[2] == False:
                return (self.header, bytes(), False)

        return (self.header, self.content, True)

    def send_request(self):
        """
        Send the HTTP request to the server over the socket

        :rtype: bool
        :returns: success status
        """

        if self.state != self.STATE_INIT:
            self.logger.error(
                "Attempt to make request when not in STATE_INIT: {}".format(
                    self.host))
            return False

        self.original_timeout = self.sock.gettimeout()
        self.sock.settimeout(self.SOCKET_TIMEOUT)

        self.request = self.HTTP_NEWLINE.join(
            self.HTTP_REQUEST_PROTOTYPE[self.user_agent])
        self.request = self.request.format(method = self.method,
            hostname = self.host)

        self.logger.debug("Sending GET request to: {}".format(self.host))
        try:
            self.sock.send(bytes(self.request, 'ASCII'))
        except ConnectionResetError:
            self.logger.debug("Connection reset while sending request: {}"\
                .format(self.host))
            self.sock.settimeout(self.original_timeout)
            self.state = self.STATE_ERROR
            return False
        except socket.timeout:
            self.logger.debug("Timeout occured while sending request: {}"\
                .format(self.host))
            self.sock.settimeout(self.original_timeout)
            self.state = self.STATE_ERROR
            return False

        self.state = self.STATE_REQUEST_MADE
        return True

    def receive_header(self):
        """
        Retrieve the HTTP response header from the server

        :rtype: tuple(str, bytes, bool)
        :returns: the tuple (header, bytes(), status). Second value will always
            be an empty bytes object.
        """


        if self.state != self.STATE_REQUEST_MADE:
            self.logger.error(
                "Attempt to get header when not in STATE_REQUEST_MADE: {}"\
                .format(self.host))
            return ('', bytes(), False)

        self.logger.debug("Retrieving header from {}".format(self.host))

        self.header = ''
        while not self._detect_end_of_header(self.header):
            try:
                new_char = self.sock.recv(1).decode('iso-8859-1')
            except ConnectionResetError:
                self.logger.debug("Connection reset while getting header: {}"\
                    .format(self.host))
                self.sock.settimeout(self.original_timeout)
                self.state = self.STATE_ERROR
                return (self.header, bytes(), False)
            except socket.timeout:
                self.logger.debug("Timeout occured while getting header: {}"\
                    .format(self.host))
                self.sock.settimeout(self.original_timeout)
                self.state = self.STATE_ERROR
                return (self.header, bytes(), False)
            except UnicodeDecodeError:
                self.logger.debug("Error while decoding header: {}"\
                    .format(self.host))
                self.sock.settimeout(self.original_timeout)
                self.state = self.STATE_ERROR
                return (self.header, bytes(), False)
            if new_char == '':
                self.logger.debug("Connection closed while getting header: {}"\
                    .format(self.host))
                self.sock.settimeout(self.original_timeout)
                self.state = self.STATE_ERROR
                return (self.header, bytes(), False)

            # if everything went fine
            self.header = self.header + new_char

        if self.method == 'HEAD':
            self.sock.settimeout(self.original_timeout)
        self.state = self.STATE_RETRIEVED_HEADER
        return (self.header, bytes(), True)

    def receive_content(self):
        """
        Retrieve the HTTP response content from the server

        :rtype: tuple(str, bytes, bool)
        :returns: the tuple (header, content, status).
        """

        if self.state != self.STATE_RETRIEVED_HEADER:
            self.logger.error(
                "Attempt to get content when not in STATE_RETRIEVED_HEADER: {}"\
                .format(self.host))
            return ('', bytes(), False)

        if self.method == 'HEAD':
            self.logger.warning('Attempt to get content for HEAD request: {}'\
                .format(self.host))
            return ('', bytes(), False)

        bytes_to_receive = self._get_content_length(self.header)
        self.logger.debug("Retrieving {} bytes of content from {}".format(
                bytes_to_receive, self.host))

        self.content = bytes()

        if bytes_to_receive == 0:
            self.sock.settimeout(self.original_timeout)
            self.state = self.STATE_RETRIEVED_CONTENT
            return (self.header, bytes(), True)

        try:
            response = self.sock.recv(bytes_to_receive)
        except ConnectionResetError:
            self.logger.debug("Connection reset while getting content: {}"\
                .format(self.host))
            self.sock.settimeout(self.original_timeout)
            self.state = self.STATE_ERROR
            return (self.header, bytes(), False)
        except socket.timeout:
            self.logger.debug("Timeout occured while getting content: {}"\
                .format(self.host))
            self.sock.settimeout(self.original_timeout)
            self.state = self.STATE_ERROR
            return (self.header, bytes(), False)
        if response == bytes():
            self.logger.debug("Connection closed while getting content: {}"\
                .format(self.host))
            self.sock.settimeout(self.original_timeout)
            self.state = self.STATE_ERROR
            return (self.header, bytes(), False)

        self.content = response

        self.logger.debug("Done with retrieving content from {}"\
            .format(self.host))

        self.sock.settimeout(self.original_timeout)
        self.state = self.STATE_RETRIEVED_CONTENT
        return (self.header, self.content, True)

    @staticmethod
    def _detect_end_of_header(response):
        """
        Returns true if the end of the header section of a HTTP resonse is detected

        Checks if `response` ends in two consecutive newlines.
        :param str response: the (partial) response from the server
        :rtype: bool
        :returns: true is the `response` ends in two consecutive newlines.
        """
        if response.endswith('\n'*2): return True
        if response.endswith('\r\n'*2): return True
        return False

    @staticmethod
    def _get_content_length(header):
        """
        Returns the value of the 'Content-Length' field in a HTTP header.

        returns 0 if the 'Content-Lenght' field was not present or could not
        be decoded.
        :param str header: a http header
        :rtype: int
        :returns: the value of the 'Content-Lenght' field
        """

        logger=logging.getLogger('http')
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

# Just some debugging stuff, you can probably ignore this.
if __name__ == "__main__":

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)

    HOST = "www.wordpress.com"
    PORT = 80

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect((HOST, PORT))

    request = Http_Request(s, HOST, method = 'HEAD')
    response = request.run()

    print(response)
