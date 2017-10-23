ForgeSpider Development
=======================

ForgeSpider plugins use Scapy to send forged packets to targets.

Plugin Metadata
---------------

As well as the common metadata, ForgeSpider plugins also require a ``packets``
variable, containing the number of different packets that should be generated
for each target.

For example, if you had two different packets to be sent:

.. code-block:: python

    class ForgeSpiderPlugin(ForgeSpider, PluggableSpider):
        packets = 2

Packet Forging
--------------

As ForgeSpider uses Scapy, you will need to import any features from Scapy you
wish to use in order to construct your packets. Scapy provides a flexible
toolbox for packet forging, to learn more please refer to the Scapy project's
documentation.

The heart of a ForgeSpider is the ``forge()`` function. This function takes two
arguments, the job containing the target information and the sequence number.
This function will be called the number of times set in the `packets` metadata
variable and `seq` will be set to the number of times the function has been
called for this job.

The function must return a Scapy Layer 3 packet. As a very basic example, a
function that forges a TCP SYN first, then a TCP RST:

.. code-block:: python

    def forge(self, job, seq):
        sport = 0
        while sport < 1024:
            sport = int(RandShort())
        l4 = TCP(sport=sport, dport=job['dp'])
        ip = IP(src=self.source[0], dst=job['dip'])
        if seq == 0:
            l4.flags = "S"
        if seq == 1:
            l4.flags = "R"
        return ip/l4

As jobs may be for both IPv4 and IPv6 targets, you should account for this and
build your packets using the correct Scapy functions for the IP version.
ForgeSpider also supports the ``--connect`` option and you can use this to
modify the type of packets generated in the forge function.
