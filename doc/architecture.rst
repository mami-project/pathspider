.. architecture:

Architecture
============

The PATHspider architecture has four components, illustrated in
:ref:`the diagram below <figarch>`: the :func:`configurator
<pathspider.base.Spider.configurator>`, the :func:`workers
<pathspider.base.Spider.worker_thread>`, the :class:`observer
<pathspider.observer.Observer>` and the :func:`merger
<pathspider.base.Spider.merger_thread>`. Each component is implemented as one or more
threads, launched when PATHspider starts.

.. figarch:

.. figure:: _static/pathspider_arch.png
   :align: center
   :alt: Overview of PATHspider architecture
   :figclass: align-center
   :height: 400px

   An overview of the PATHspider architecture

For each target hostname and/or address, with port numbers where appropriate,
PATHspider enqueues a job, to be distributed amongst the worker threads when
available.  Each worker performs one connection with the "A" configuration
and one connection with the "B" configuration. The "A" configuration will
always be connected first and serves as the base line measurement, followed by
the "B" configuration. This allows detection of hosts that do not respond
rather than failing as a result of using a particular transport protocol or
extension. These sockets remain open for a post-connection operation.

Some transport options require a system-wide parameter change, for example
enabling ECN in the Linux kernel.  This requires locking and synchronisation.
Using semaphores, the configurator waits for each worker to complete an
operation and then changes the state to perform the next batch of operations.
This process cycles continually until no more jobs remain. In a typical
experiment, multiple workers (on the order of hundreds) are active, since much
of the time in a connection test is spent waiting for an answer for the
target or a timeout to fire.

In addition, packets are separately captured for analysis by the observer using
`Python bindings for libtrace
<https://www.cs.auckland.ac.nz/~nevil/python-libtrace/>`_. First, the observer
assigns each incoming packet to a flow based on the source and destination
addresses, as well as the TCP, UDP or SCTP ports when available. The packet and
its associated flow are then passed to a function chain. The functions in this
chain may be simple functions, such as counting the number of packets or octets
seen for a flow, or more complex functions, such as recording the state of
flags within packets and analysis based on previously observed packets in the
flow. For example, a function may record both an ECN negotiation attempt and
whether the host successfully negotiated use of ECN.

A function may alert the observer that a flow should have completed and that
the flow information can be matched with the corresponding job record and
passed to the merger. The merger extracts the fields needed for a particular
measurement campaign from the records produced by the worker and the observer.

