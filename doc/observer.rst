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

If a function returns False, the Observer will consider the flow to be finished
and will pass it to be merged with the job record after a short delay.

Observer Implementation
-----------------------

.. autoclass:: pathspider.observer.Observer
   :members:
   :undoc-members:
   :special-members: __init__
