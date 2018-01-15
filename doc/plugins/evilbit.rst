Evil Bit Plugin
===============

The Evil Bit refers to the unused high-order bit of the IP fragment offset
field in the IP header. It was defined in RFC3514 on the 1st of April 2003.

The Evil Bit plugin for PATHspider aims to detect breakage in the Internet due
to the use of reserved bit in the IP fragment offset field.

Usage Example
-------------

.. note:: The path given to the example list of web servers is taken from a
          Debian GNU/Linux installation and may differ on your computer. These
          are the same examples that can be found in the `examples/` directory
          of the source distribution.

To use the EvilBit plugin, specify ``evilbit`` as the plugin to use on the
command-line:

.. code-block:: shell

 pspdr measure -i eth0 evilbit </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

This will run two TCP connections for each job input, one with the evil bit not
set and one with the evil bit set (indicating the packet's malicious intent).

Supported Connection Modes
--------------------------

This plugin supports the following connection modes:

 * tcp - Performs only a TCP 3WHS
 * dnsudp - Performs a DNS query using UDP

To use an alternative connection mode, add the ``--connect`` argument to the
invocation of PATHspider:

.. code-block:: shell

 pspdr measure -i eth0 evilbit --connect tcp </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

Output Conditions
-----------------

The following conditions are generated for the evilbit plugin:

evilbit.X.connectivity.Y
~~~~~~~~~~~~~~~~~~~~~~~~

For each connection that was observed by PATHspider, a connectivity condition
will be generated to indicate whether or not connectivity with the evil bit set
was successful validated against a connection without the evil bit set.

Y may have the following values:

 * works - Both connections succeeded
 * broken - Baseline connection succeeded where experimental connection failed
 * offline - Both connections failed
 * transient - Baseline connection failed where experimental connection
   succeeded (this can be used to give an indication of transient failure rates
   included in the "broken" set)

evilbit.mark.X
~~~~~~~~~~~~~~

A condition is generated to show whether the evil bit was set on the return
path for the experimental connection. X can have two values, "seen" or
"not_seen".

Notes
-----

* The evil bit is set using packet forging library Scapy. Due to the lack of a
  TCP state machine, connection types such as HTTP are not available.
