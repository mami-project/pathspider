ECN Plugin
==========

Explicit Congestion Notification (ECN) is an extension to the Internet Protocol
and to the Transmission Control Protocol. [RFC3168]_ ECN allows end-to-end
notification of network congestion without dropping packets.  ECN is an
optional feature that may be used between two ECN-enabled endpoints when the
underlying network infrastructure also supports it.

Conventionally, TCP/IP networks signal congestion by dropping packets. When ECN
is successfully negotiated, an ECN-aware router may set a mark in the IP header
instead of dropping a packet in order to signal impending congestion. The
receiver of the packet echoes the congestion indication to the sender, which
reduces its transmission rate as if it detected a dropped packet.

Rather than responding properly or ignoring the bits, some outdated or faulty
network equipment has historically dropped or mangled packets that have ECN
bits set. As of 2015, measurements suggested that the fraction of web servers
on the public Internet for which setting ECN prevents network connections had
been reduced to less than 1%. [Trammell15]_

The ECN plugin for PATHspider aims to detect breakage in the Internet due to
the use of ECN.

Usage Example
-------------

.. note:: The path given to the example list of web servers is taken from a
          Debian GNU/Linux installation and may differ on your computer. These
	  are the same examples that can be found in the `examples/` directory
          of the source distribution.

To use the ECN plugin, specify ``ecn`` as the plugin to use on the command-line:

.. code-block:: shell

 pspdr measure -i eth0 ecn </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

This will run two TCP connections for each job input, one with ECN disabled in
the kernel TCP/IP stack and one with ECN enabled in the kernel TCP/IP stack.

Supported Connection Modes
--------------------------

This plugin supports the following connection modes:

 * http - Performs a GET request
 * https - Performs a GET request using HTTPS
 * tcp - Performs only a TCP 3WHS
 * dnstcp - Performs a DNS query using TCP

To use an alternative connection mode, add the ``--connect`` argument to the
invocation of PATHspider:

.. code-block:: shell

 pspdr measure -i eth0 ecn --connect tcp </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

Output Conditions
-----------------

The following conditions are generated for the ECN plugin:

ecn.connectivity.Y
~~~~~~~~~~~~~~~~~~

For each connection that was observed by PATHspider, a connectivity condition
will be generated to indicate whether or not connectivity was successful using
ECN against a connection not using ECN.

Y may have the following values:

 * works - Both connections succeeded
 * broken - Baseline connection succeeded where experimental connection failed
 * offline - Both connections failed
 * transient - Baseline connection failed where experimental connection
   succeeded (this can be used to give an indication of transient failure rates
   included in the "broken" set)


ecn.negotiation.Y
~~~~~~~~~~~~~~~~~

For each experimental connection that was observed to have a response by PATHspider, a
condition is generated to show whether or not ECN negotiation succeded between
the two hosts.

Y may have the following values:
 
 * succeeded -  ECN negotiation succeeded
 * reflected -  ECN negotiation failed, with both ECE and CWR set on reply SYN
 * failed - ECN negotiation failed

ecn.ipmark.X.Y
~~~~~~~~~~~~~~

For each connection that was observed by PATHspider, a condition is generated
to record the ECN marks seen.  Y has two possible values, "seen" or "not_seen",
corresponding to whether or not mark X was encountered.

X may have the following values:

 * ect0 - ECN Capable Transport (0)
 * ect1 - ECN Capable Transport (1)
 * ce - Congestion Experienced

Notes
-----

* ECN behaviour is implemented by the host kernel for PATHspider, and is
  switched by a ``sysctl`` call.  PATHspider makes no guarantees the the
  configuration state is consistent once it has been set, though you can use
  the forward SYN flags in the output to validate the results within a
  reasonably high level of certainty that everything behaved correctly.
