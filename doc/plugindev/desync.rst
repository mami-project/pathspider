DesynchronizedSpider Development
================================

DesynchronizedSpider plugins modify the connection logic in order to change the
behaviour of the connections. There is no global state synchronisation and so a
DesynchronizedSpider can be more efficient than a SynchronizedSpider.

Connection Functions
--------------------

Connection functions are at the heart of a DesynchronizedSpider plugin. These
use a connection helper (or custom connection logic) to generate traffic
towards with a target to get a reply from the target.

One function should be written for each connection to be made, usually with at
least two function to provide a baseline followed by an experimental
connection.

By convention, functions should be prefixed with `conn_` to ensure there are no
conflicts. After declaring the functions, you must then set the connections
metadata variable with pointers to each of the connection functions.

The following shows the relevant portions of the H2 plugin, which uses this
framework:

.. code-block:: python

    class H2(DesynchronizedSpider, PluggableSpider):
        def conn_no_h2(self, job, config):  # pylint: disable=unused-argument
            if self.args.connect == "http":
                return connect_http(self.source, job, self.args.timeout)
            if self.args.connect == "https":
                return connect_http(self.source, job, self.args.timeout)
            else:
                raise RuntimeError("Unknown connection mode specified")
    
        def conn_h2(self, job, config): # pylint: disable=unused-argument
            curlopts = {pycurl.HTTP_VERSION: pycurl.CURL_HTTP_VERSION_2_0}
            curlinfos = {pycurl.INFO_HTTP_VERSION}
            if self.args.connect == "http":
                return connect_http(self.source, job, self.args.timeout, curlopts, curlinfos)
            if self.args.connect == "https":
                return connect_https(self.source, job, self.args.timeout, curlopts, curlinfos)
            else:
                raise RuntimeError("Unknown connection mode specified")
    
        connections = [conn_no_h2, conn_h2]
