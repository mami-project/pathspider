ECN Plugin
==========

Explicit Congestion Notification (ECN) is an extension to the Internet Protocol
and to the Transmission Control Protocol. [RFC3186]_ ECN allows end-to-end
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

To use the ECN plugin, specify ``ecn`` as the plugin to use on the command-line:

.. code-block:: shell

 pathspider ecn </usr/share/doc/pathspider/examples/webtest.csv >results.txt

This will run two TCP connections for each job input, one with ECN disabled in
the kernel TCP/IP stack and one with ECN enabled in the kernel TCP/IP stack.

Output Fields
-------------

In addition to the :ref:`default output fields <defaultoutput>`, the ECN
plugin also provides the following fields for each flow:

+---------------+-------------------------------------------------------------+
| Key           | Description                                                 |
+===============+=============================================================+
| fwd_ez        | ECT(0) was observed in the forward direction.               |
+---------------+-------------------------------------------------------------+
| rev_ez        | ECT(0) was observed in the reverse direction.               |
+---------------+-------------------------------------------------------------+
| fwd_eo        | ECT(1) was observed in the forward direction.               |
+---------------+-------------------------------------------------------------+
| rev_eo        | ECT(1) was observed in the reverse direction.               |
+---------------+-------------------------------------------------------------+
| fwd_ce        | CE was observed in the forward direction.                   |
+---------------+-------------------------------------------------------------+
| rev_ce        | CE was observed in the reverse direction.                   |
+---------------+-------------------------------------------------------------+
| fwd_syn_flags | The SYN flags observed in the forward direction.            |
+---------------+-------------------------------------------------------------+
| rev_syn_flags | The SYN flags observed in the reverse direction.            |
+---------------+-------------------------------------------------------------+
| fwd_fin       | A FIN flag was observed in the forward direction.           |
+---------------+-------------------------------------------------------------+
| rev_fin       | A FIN flag was observed in the reverse direction.           |
+---------------+-------------------------------------------------------------+
| fwd_rst       | A RST flag was observed in the forward direction.           |
+---------------+-------------------------------------------------------------+
| rev_rst       | A RST flag was observed in the reverse direction.           |
+---------------+-------------------------------------------------------------+
| tcp_completed | A complete 3WHS for TCP was observed to be successful.      |
+---------------+-------------------------------------------------------------+

Notes
-----

* ECN behaviour is implemented by the host kernel for PATHspider, and is
  switched by a ``sysctl`` call.  PATHspider makes no guarantees the the
  configuration state is consistent once it has been set, though you can use
  the forward SYN flags in the output to validate the results within a
  reasonably high level of certainty that everything behaved correctly.
