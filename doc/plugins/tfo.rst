TFO Plugin
==========

TCP Fast Open (TFO) is an extension to speed up the opening of successive
Transmission Control Protocol (TCP) connections between two endpoints. It works
by using a TFO cookie (a TCP option), which is a cryptographic cookie stored on
the client and set upon the initial connection with the server. [RFC7413]_

When the client later reconnects, it sends the initial SYN packet along with
the TFO cookie data to authenticate itself. If successful, the server may start
sending data to the client even before the reception of the final ACK packet of
the three-way handshake, skipping that way a round-trip delay and lowering the
latency in the start of data transmission.

The TFO plugin for PATHspider aims to detect breakage in the Internet due to
the use of TCP Fast Open.

Usage Example
-------------

To use the DSCP plugin, specify ``tfo`` as the plugin to use on the command-line:

.. code-block:: shell

 pathspider tfo </usr/share/doc/pathspider/examples/webtest.csv >results.txt

For the baseline test, the plugin will perform a TCP connection to the target
host. For the experimental case, the plugin will perform two TCP connections to
the target host. The first experimental connection is run to acquire a TFO
cookie and the second to check that it can be used.

Output Fields
-------------

In addition to the :ref:`default output fields <defaultoutput>`, the TFO
plugin also provides the following fields for each flow:

+---------------+-------------------------------------------------------------+
| Key           | Description                                                 |
+===============+=============================================================+
| tfo_synkind   |                                                             |
+---------------+-------------------------------------------------------------+
| tfo_ackkind   |                                                             |
+---------------+-------------------------------------------------------------+
| tfo_synclen   |                                                             |
+---------------+-------------------------------------------------------------+
| tfo_ackclen   |                                                             |
+---------------+-------------------------------------------------------------+
| tfo_seq       |                                                             |
+---------------+-------------------------------------------------------------+
| tfo_dlen      |                                                             |
+---------------+-------------------------------------------------------------+
| tfo_ack       |                                                             |
+---------------+-------------------------------------------------------------+

