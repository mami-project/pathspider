.. _observer:

Observer
========

Observer Function Chains
------------------------

PATHspider's observer will accept functions and pass python-libtrace dissected
packets along with the associated flow record to them for every packet
recieved.

+----------------------+--------------------------------------------------+
| Function Chain       | Description                                      |
+======================+==================================================+
| new_flow_chain       | Functions to initialise fields in the flow       |
|                      | record for new flows.                            |
+----------------------+--------------------------------------------------+
| ip4_chain            | Functions to record details from IPv4 headers.   |
+----------------------+--------------------------------------------------+
| ip6_chain            | Functions to record details from IPv6 headers.   |
+----------------------+--------------------------------------------------+
| tcp_chain            | Functions to record details from TCP headers.    |
+----------------------+--------------------------------------------------+
| udp_chain            | Functions to record details from UDP headers.    |
+----------------------+--------------------------------------------------+
| l4_chain             | Functions to record details from other layer     |
|                      | 4 headers.                                       |
+----------------------+--------------------------------------------------+

Quickstart
----------

The :mod:`pathspider.observer` module provides
:func:`pathspider.observer.simple_observer` which allows the creation of a very
simple Observer during development of the other portions of the plugin. There
are two simple examples of observer functions that are used in the observer
created by this function.

The :func:`pathspider.observer.basic_flow` function simply creates the inital
state for the flow record, extracting the 5-tuple and initialising counters.
The counters are used by the :func:`pathspider.observer.basic_count` function
that counts the number of packets and octets seen in each direction.

Initialisation happens in the ``new_flow_chain`` and the counts happen in the
``ip4_chain`` and ``ip6_chain``.

Writing Observer Functions
--------------------------

When you are ready to write functions for the observer, first identify which
data should be stored in the flow record. This is a :class:`dict` that is made
available for every call to an observer function for a particular flow and
not shared across flows. Once the flow is completed, this is the record that
will be returned to the merger.

Handling New Flows
^^^^^^^^^^^^^^^^^^

The flow record should be initialised when a new flow has been identified. The
functions in the ``new_flow_chain`` are called, in sequence, when a new flow
is identified by the Observer. These functions are passed two arguments:
``rec`` - the empty flow record, and ``ip`` - the IP header.

At a minimum, this should contain::

    def example_flow(rec, ip):
        # Extract addresses and ports
        (rec['sip'], rec['dip'], rec['proto']) = (str(ip.src_prefix), str(ip.dst_prefix), ip.proto)
        (rec['sp'], rec['dp']) = extract_ports(ip)

*Note: You will need to import :func:`pathspider.observer.extract_ports` to use
this example.*

Writing Analysis Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^

You should familiarise yourself with the `python-libtrace documentation
<https://www.cs.auckland.ac.nz/~nevil/python-libtrace/>`_. The analysis
functions all follow the same function prototype with ``rec`` - the empty flow
record, ``x`` - the header, and ``rev`` - boolean value indicating the
direction the packet travelled (i.e. Was the packet in the reverse direction?).

The only difference in these functions is the header that is passed, as a
python-libtrace object, to the function. The same flow record is always passed
for each call for the same flow, regardless of which function chain the
function is in.

An example function is the implementation of
:func:`pathspider.observer.basic_flow`.

If a function returns False, as it has identified the end of the flow, the
Observer will consider the flow to be finished and will pass it to be merged
with the job record after a short delay. This might occur, for TCP flows, when
both FIN packets have been seen.

Observer Implementation
-----------------------

.. automodule:: pathspider.observer
   :members:
   :undoc-members:
   :special-members: __init__
