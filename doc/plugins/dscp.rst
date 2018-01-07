DSCP Plugin
===========

Differentiated services or DiffServ [RFC2474]_ is a networking architecture
that specifies a simple, scalable and coarse-grained mechanism for classifying
and managing network traffic and providing quality of service (QoS) on modern
IP networks.  DiffServ can, for example, be used to provide low-latency to
critical network traffic such as voice or streaming media while providing
simple best-effort service to non-critical services such as web traffic or file
transfers.

DiffServ uses a 6-bit differentiated services code point (DSCP) in the 8-bit
differentiated services field (DS field) in the IP header for packet
classification purposes. The DS field and ECN field replace the outdated IPv4
TOS field. [RFC3260]_

The DSCP plugin for PATHspider aims to detect breakage in the Internet due to
the use of a non-zero DSCP codepoint.

Usage Example
-------------

.. note:: The path given to the example list of web servers is taken from a
          Debian GNU/Linux installation and may differ on your computer. These
          are the same examples that can be found in the `examples/` directory
          of the source distribution.

To use the DSCP plugin, specify ``dscp`` as the plugin to use on the command-line:

.. code-block:: shell

 pspdr measure -i eth0 dscp </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

This will run two HTTP GET request connections over TCP for each job input, one
with the DSCP set to zero (best-effort) and one with the DSCP set to 46
(expedited forwarding). If you would like to specify the code point for use on
the experimental flow, you may do this with the ``--codepoint`` option. For
example, to use 42:

.. code-block:: shell

 pspdr measure -i eth0 dscp --codepoint 42 </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

Supported Connection Modes
--------------------------

This plugin supports the following connection modes:

 * http - Performs a GET request
 * tcp - Performs only a TCP 3WHS
 * dnsudp - Performs a DNS query using UDP
 * dnstcp - Performs a DNS query using TCP

To use an alternative connection mode, add the ``--connect`` argument to the
invocation of PATHspider:

.. code-block:: shell

 pspdr measure -i eth0 dscp --connect tcp </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

Output Conditions
-----------------

The following conditions are generated for the DSCP plugin:

dscp.X.connectivity.Y
~~~~~~~~~~~~~~~~~~~~~

For each connection that was observed by PATHspider, a connectivity condition
will be generated to indicate whether or not connectivity was successful using
codepoint X validated against a connection using codepoint 0 (zero).

Y may have the following values:

 * works - Both connections succeeded
 * broken - Baseline connection succeeded where experimental connection failed
 * offline - Both connections failed
 * transient - Baseline connection failed where experimental connection
   succeeded (this can be used to give an indication of transient failure rates
   included in the "broken" set)

dscp.X.replymark:
~~~~~~~~~~~~~~~~~

For each connection that was observed to have a response by PATHspider, a
condition is generated to show values of codepoints set on response packets
when codepoint X was set.

Notes
-----

* DSCP marking is performed using the ``mangle`` table in ``iptables``.
  The ``config_zero`` function will flush this table. PATHspider makes no
  guarantees the the configuration state is consistent once it has been set,
  though you can use the forward path markings in the output to validate the
  results within a reasonably high level of certainty that everything
  behaved correctly.
