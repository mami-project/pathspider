UDP Zero Checksum Plugin
========================

UDP uses a 16-bit field to store a checksum for data integrity.  The UDP
checksum field [RFC768]_ is calculated using information from the pseudo-IP
header, the UDP header, and the data is padded at the end if necessary to
make a multiple of two octets. The checksum is optional when using IPv4, and
if unused a UDP checksum field carrying all zeros indicates the transmitter did
not compute the checksum.

The UDPZero plugin for PATHspider aims to detect breakage in the Internet due
to the use a zero-checksum field.

Usage Example
-------------

.. note:: The path given to the example list of web servers is taken from a
          Debian GNU/Linux installation and may differ on your computer. These
          are the same examples that can be found in the `examples/` directory
          of the source distribution.

To use the UDPZero plugin, specify ``udpzero`` as the plugin to use on the
command-line:

.. code-block:: shell

 pspdr measure -i eth0 udpzero </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

This will run two DNS request connections over UDP for each job input, one with
the checksum field unmodified and one with the checksum field set to all zeros.

Supported Connection Modes
--------------------------

This plugin supports the following connection modes:

 * dnsudp - Performs a DNS query using UDP

Output Conditions
-----------------

The following conditions are generated for the UDPZero plugin:

udpzero.connectivity.Y
~~~~~~~~~~~~~~~~~~~~~~

For each connection that was observed by PATHspider, a connectivity condition
will be generated to indicate whether or not connectivity was successful using
UDP zero-checksum validated against a connection with the calculated checksum
left intact.

Y may have the following values:

 * works - Both connections succeeded
 * broken - Baseline connection succeeded where experimental connection failed
 * offline - Both connections failed
 * transient - Baseline connection failed where experimental connection
   succeeded (this can be used to give an indication of transient failure rates
   included in the "broken" set)

Notes
-----

* Setting the UDP checksum field to all zeros is performed using Python library
  Scapy.
