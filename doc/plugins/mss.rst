TCP Maximum Segment Size Plugin
===============================

The Transmission Control Protocol (TCP) Maximum Segment Size (MSS) option was
one of the TCP options defined in the very first specification for TCP
[RFC793]_:

  If this option is present, then it communicates the maximum
  receive segment size at the TCP which sends this segment.
  This field must only be sent in the initial connection request
  (i.e., in segments with the SYN control bit set).  If this
  option is not used, any segment size is allowed.

Due to the prevalent blocking of ICMP throughout the Internet (if you do this,
please stop!), path maximum transmission unit (PMTU) discovery often fails to
correctly determine the MTU that can safely be used between two hosts. As an
alternative strategy, routers can rewrite the TCP MSS option present on SYN
packets to ensure that the MSS seen by the receiving end of the packets is not
greater than that which is supported on the links connected to that router.

The MSS plugin for PATHspider aims to discover the value of MSS that is
received when connecting to hosts using TCP and compares this to the local
MTU to determine if the received MSS is lower (possibly indicating the clamping
behaviour described above), equal or greater (possibly indicating an unsafe
MSS) than the local MSS.

Usage Example
-------------

.. note:: The path given to the example list of web servers is taken from a
          Debian GNU/Linux installation and may differ on your computer. These
          are the same examples that can be found in the `examples/` directory
          of the source distribution.

To use the MSS plugin, specify ``mss`` as the plugin to use on the command-line:

.. code-block:: shell

 pspdr measure -i eth0 mss </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

This will open a TCP connection for each job input, recording the received MSS
for each reply.

Supported Connection Modes
--------------------------

This plugin supports the following connection modes:

 * tcp - Performs a TCP connection
 * http - Performs a GET request
 * https - Performs a GET request using HTTPS
 * dnstcp - Performs a DNS query using TCP

To use an alternative connection mode, add the ``--connect`` argument to the
invocation of PATHspider:

.. code-block:: shell

 pspdr measure -i eth0 mss --connect tcp </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

Output Conditions
-----------------

The following conditions are generated for the MSS plugin:

mss.connectivity.Y
~~~~~~~~~~~~~~~~~~

For each connection that was observed by PATHspider, a connectivity condition
will be generated to indicate whether or not connectivity was successful using
TFO validated against a connection not using TFO.

Y may have the following values:

 * online - The connection succeeded
 * offline - The connection failed

mss.option.X.value:Y
~~~~~~~~~~~~~~~~~~~~

For each connection that was observed to have a response by PATHspider and
observed to have an MSS option in the TCP header, a condition is generated to
show the value of the MSS option.

X can have two values, "local" or "remote", idicating whther the option was
sent locally or received from the remote target (possibly having been rewritten
on the path). Y is the value of the option.

mss.option.received.X
~~~~~~~~~~~~~~~~~~~~~

For each connection that was observed to have a response by PATHspider, a
condition is generated to show whether the MSS option was absent or present.
If present, it will be compared to the local MSS. X can have the following
values:

 * absent - The response from the remote target did not contain an MSS option
   in the TCP header.
 * unchanged - The MSS option received from the remote target contained the
   same value as the local MSS.
 * inflated - The MSS option received from the remote target contained a greater
   MSS than the local MSS.
 * deflated - The MSS option received from the remote target contained a lower
   MSS than the local MSS.
