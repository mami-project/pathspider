EvilBit Plugin
==============

The EvilBit refers to the unused high-order bit of the IP fragment offset field 
in the IP header. It was defined in RFC3514 on the 1st of April 2003.	

The EvilBit plugin for PATHspider aims to detect breakage in the Internet due to
the use of reserved bit in the IP fragment offset field.

Usage Example
-------------

To use the EvilBit plugin, specify ``evilbit`` as the plugin to use on the command-line:

.. code-block:: shell

 pathspider evilbit </usr/share/doc/pathspider/examples/webtest.csv >results.txt

This will run two TCP connections for each job input, one with the evil bit not set
and one with the evil bit set (indicating the packet's malicious intent).

Output Fields
-------------

In addition to the :ref:`default output fields <defaultoutput>`, the EvilBit
plugin also provides the following fields for each flow:

+-------------------+-------------------------------------------------------------+
| Key               | Description                                                 |
+===================+=============================================================+
| evilbit_syn_fwd   | True if the evil bit was set in the IP header for a TCP SYN |
|                   | in the forward direction                                    |
+-------------------+-------------------------------------------------------------+
| evilbit_syn_rev   | True if the evil bit was set in the IP header for a TCP SYN |
|                   | in the forward direction                                    |
+-------------------+-------------------------------------------------------------+
| evilbit_data_fwd  | True if the evil bit was set in the IP header for a data    |
|                   | packet in the forward direction.                            | 
+-------------------+-------------------------------------------------------------+
| evilbit_data_rev  | True if the evil bit was set in the IP header for a data    |
|                   | packet in the reverse direction.                            |
+-------------------+-------------------------------------------------------------+

