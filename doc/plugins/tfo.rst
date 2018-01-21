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

The TFO plugin for PATHspider aims to detect connectivity breakage due to the
the use of TCP Fast Open, implementation of TCP Fast Open, and TFO
implementation anomalies.

Usage Example
-------------

.. note:: The path given to the example list of web servers is taken from a
          Debian GNU/Linux installation and may differ on your computer. These
          are the same examples that can be found in the `examples/` directory
          of the source distribution.

To use the TFO plugin, specify ``tfo`` as the plugin to use on the command-line:

.. code-block:: shell

 pspdr measure -i eth0 tfo </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

This will run three DNS queries over TCP for each job input, one
without using TCP Fast Open and two using it, with the first connection using
it used to prime the system to make a 0-RTT connection on the second.

Supported Connection Modes
--------------------------

This plugin supports the following connection modes:

 * dnstcp - Performs a DNS query using TCP

To use an alternative connection mode, add the ``--connect`` argument to the
invocation of PATHspider:

.. code-block:: shell

 pspdr measure -i eth0 tfo --connect tcp </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

Output Conditions
-----------------

The following conditions are generated for the TFO plugin:

tfo.connectivity.Y
~~~~~~~~~~~~~~~~~~

For each connection that was observed by PATHspider, a connectivity condition
will be generated to indicate whether or not connectivity was successful using
TFO validated against a connection not using TFO.

Y may have the following values:

 * works - Both connections succeeded
 * broken - Baseline connection succeeded where experimental connection failed
 * offline - Both connections failed
 * transient - Baseline connection failed where experimental connection
   succeeded (this can be used to give an indication of transient failure rates
   included in the "broken" set)

tfo.cookie.X
~~~~~~~~~~~~

For each connection that was observed to have a response by PATHspider, a
condition is generated to show whether the TFO cookie was received on response packets.

X can have two values, "received" or "not_received", idicating whther the client 
received a TFO cookie after sending the Fast Open Cookie Request option.


tfo.syndata.X
~~~~~~~~~~~~~

For each connection that was observed to have a response by PATHspider, a
condition is generated to show whether the TFO cookie was acknowledged when
resending to the tested host.

 * acked - The server sends a SYN-ACK acknowledging the TFO cookie
 * not_acked - The server sends a SYN-ACK not acknowledging the TFO cookie
 * failed - The server does not send a SYN-ACK

Notes
-----

* TCP Fast Open is set using a socket option options. Through passive
  observation it should be possible to verify that TCP Fast Open is indeed
  being used.
