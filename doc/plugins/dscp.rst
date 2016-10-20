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

To use the DSCP plugin, specify ``dscp`` as the plugin to use on the command-line:

.. code-block:: shell

 pathspider dscp </usr/share/doc/pathspider/examples/webtest.csv >results.txt

This will run two TCP connections for each job input, one with the DSCP set to
zero (best-effort) and one with the DSCP set to 46 (expedited forwarding). If
you would like to specify the code point for use on the experimental flow, you
may do this with the ``--codepoint`` option. For example, to use 42:

.. code-block:: shell

 pathspider dscp --codepoint 42 </usr/share/doc/pathspider/examples/webtest.csv >results.txt

Output Fields
-------------

In addition to the :ref:`default output fields <defaultoutput>`, the DSCP
plugin also provides the following fields for each flow:

+---------------+-------------------------------------------------------------+
| Key           | Description                                                 |
+===============+=============================================================+
| fwd_syn_dscp  | DiffServ code point as observed on the forward path for the |
|               | first SYN in the flow.                                      |
+---------------+-------------------------------------------------------------+
| rev_syn_dscp  | DiffServ code point as observed on the reverse path for the |
|               | first SYN in the flow (likely to be a SYN/ACK).             |
+---------------+-------------------------------------------------------------+
| fwd_data_dscp | DiffServ code point as observed on the forward path for the |
|               | first data packet (i.e. with a payload) in the flow.        |
+---------------+-------------------------------------------------------------+
| rev_data_dscp | DiffServ code point as observed on the reverse path for the |
|               | first data packet (i.e. with a payload) in the flow.        |
+---------------+-------------------------------------------------------------+

Notes
-----

* DSCP marking is performed using the ``mangle`` table in ``iptables``.
  The ``config_zero`` function will flush this table. PATHspider makes no
  guarantees the the configuration state is consistent once it has been set,
  though you can use the forward path markings in the output to validate the
  results within a reasonably high level of certainty that everything
  behaved correctly.
