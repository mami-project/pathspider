Resolving Target Lists
======================

Built-in DNS Resolver
---------------------

The resolver accepts input formatted as CSV in the style of the Alexa top 1
million website listing:

::

 rank,domain

The output format is the native input format for PATHspider plugins. To get
started, you can use the included example list of domains:

.. code-block:: shell

 sudo pspdr measure -i eth0 --csv dnsresolv </usr/share/doc/pathspider/examples/dnsresolvtest.csv

This built in resolver is implemented as a PATHspider measurement plugin to
demonstrate the flexibility of the plugin framework. For larger campaigns you
may instead wish to use the advanced DNS resolver available seperately.

Advanced DNS Resolver
---------------------

Hellfire is a parallelised DNS resolver. It is written in Go and for the
purpose of generating input lists to PATHspider, though may be useful for other
applications. You will require Go to be installed on your computer before you
can use Hellfire.

Installation is via ``go get``:

.. code-block:: shell

 go get pathspider.net/hellfire/...

The following input types are supported:

 * Alexa Top 1 Million Global Sites
 * Cisco Umbrella 1 Million
 * Citizen Lab Test Lists
 * OpenDNS Public Domain Lists
 * Comma-Seperated Values Files
 * Plain Text Domain Lists

More information on usage can be found at the `Hellfire website
<https://pathspider.net/hellfire/>`_.
