Flow Analysis Chains
====================

PATHspider's flow observer accepts analysis chains and passes `python-libtrace
<https://www.cs.auckland.ac.nz/~nevil/python-libtrace/>`_ dissected packets
along with the associated flow record to them for every packet recieved. The
chains that are desired should be specified in the ``chains`` attribute of
your class as a list of classes. If this list is empty, which is the default if
not overridden in your class, no flow analysis will be performed. This can be
used during early development of your plugin while you work on the traffic
generation.

When you are ready to start working with flow analysis, you will need to expand
your ``chains`` attribute. You can see this in the following example:

.. code-block:: python

 from pathspider.chains.basic import BasicChain

 class Example(SynchronizedSpider, PluggableSpider):

     name = "example"
     description = "An Example Plugin"
     version = "1.0"
     chains = [BasicChain, ...]

     ...

Depending on the types of analysis you would like to do on the packets, you
should add additional chains to the chains attribute of your plugin class.

Library Flow Analysis Chains
----------------------------

The :class:`pathspider.chains.basic.BasicChain` chain creates inital
state for the flow record, extracting the 5-tuple and counting the number of
packets and octets in each direction.  Unless you have good reason, this chain
should be included in your plugin as its fields are used by the merger to match
flow records with their corresponding jobs.

PATHspider also provides library flow analysis chains for some protocols and
extensions:

.. toctree::
   :titlesonly:

   basic.rst
   dns.rst
   dscp.rst
   ecn.rst
   icmp.rst
   tcp.rst
   tfo.rst

.. toctree::
   :hidden:

   base.rst
   noop.rst

Writing Flow Analysis Chains
----------------------------

When you are ready to write a chain for the observer, first identify which
data should be stored in the flow record. This is a :class:`dict` that is made
available for every call to a chain function for a particular flow
(identified by its 5-tuple) and not shared across flows.

Flow chains inherit from :class:`pathspider.chains.base.Chain` and provide
a series of functions for handling different types of packet.

.. autoclass:: pathspider.chains.base.Chain
   :noindex:

You should familiarise yourself with the `python-libtrace documentation
<https://www.cs.auckland.ac.nz/~nevil/python-libtrace/>`_. The analysis
functions all follow similar function prototypes with ``rec``: the flow
record, ``x``: the protocol header, and ``rev``: boolean value indicating the
direction the packet travelled (i.e. was the packet in the reverse direction?).
The exception to this rule is for ``icmp4`` and ``icmp6`` which also provide a
``q`` argument, the ICMP quotation if the message was a type that carries a
quotation otherwise this is set to ``None``.

The only requirement for a flow analysis chain is that it provides a
``new_flow()`` function. All other functions are optional. If the
``new_flow()`` function does not return True, the flow will be discarded. All
other functions must return ``True`` unless they have identified that the flow
is complete and should be passed on to the merger. If this is not easily
detectable, a timeout will pass the flow for merging after a fixed interval
where no new packets have been seen.

You can find descriptions for each of the possible chain functions in
:class:`pathspider.chains.noop.NoOpChain`:

.. autoclass:: pathspider.chains.noop.NoOpChain
   :members:
   :noindex:
