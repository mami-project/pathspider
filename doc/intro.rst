Introduction
============

Network operators increasingly rely on in-network functionality to make their
networks manageable and economically viable. These middleboxes make the
end-to-end path for traffic more opaque by making assumptions about the traffic
passing through them. This has led to an ossification of the Internet protocol
stack: new protocols and extensions can be difficult to deploy when middleboxes
do not understand them [Honda11]_. PATHspider is a software measurement tool
for active measurement of Internet path transparency to transport protocols and
transport protocol extensions, that can generate raw data at scale to determine
the size and shape of this problem.

The A/B testing measurement methodology used by PATHspider is simple: We
perform connections from a set of observation points to a set of measurement
targets using two configurations. A baseline configuration (A), usually a TCP
connection using kernel default and no extensions, tests basic connectivity.
These connections are compared to the experimental configuration (B), which
uses a different transport protocol or set of TCP extensions. These connections
are made as simultaneously as possible, to reduce the impact of transient
network changes.

PATHspider is a generalized version of the
`ecnspider <https://github.com/britram/pathtools/tree/master/pathspider/ecnspider2>`_
tool, used in previous studies to probe the paths from multiple vantage points
to web-servers [Trammell15]_ and to peer-to-peer clients [Gubser15]_ for
failures negotiating Explicit Congestion Notification (ECN) [RFC3186]_ in
TCP.

As a generalized tool for controlled experimental A/B testing of path
impairment, PATHspider fills a gap in the existing Internet active
measurement software ecosystem.  Existing active measurement platforms, such
as RIPE Atlas [RIPEAtlas]_, OONI [Filasto12]_, or
Netalyzr [Kreibich10]_, were built to measure absolute performance and
connectivity between a pair of endpoints under certain conditions. The results
obtainable from each of these can of course be compared to each other to
simulate A/B testing. However, the measurement data obtained from these
platforms provide a less controlled view than can be achieved with
PATHspider, given coarser scheduling of measurements in each state.

Given PATHspider's modular design and implementation in Python, plugins to
perform measurements for any transport protocol or extension are easy to
build and can take advantage of the rich Python library ecosystem, including
high-level application libraries, low-level socket interfaces, and packet
forging tools such as `Scapy <http://www.secdev.org/projects/scapy/>`_.

.. architecture:

Architecture
------------

The PATHspider architecture has four components, illustrated in
the diagram below the :func:`configurator
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
of the time in a connection test is spent waiting for an answer from the
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

Extensibility
-------------

PATHspider plugins are built by extending an abstract class that
implements the core behaviour, with functions for the
configurator, workers, observer, and matcher.

There are two configurator functions: ``config_zero`` and ``config_one``,
run by the configurator to prepare for each attempted connection mode.  Where
system-wide configuration is not required, the configurator provides the
semaphore-based locking functions. This makes the workers aware of the current
configuration allowing the connection functions to change based on the current
configuration mode.

There are three connection functions: ``pre_connect``, ``connect`` and
``post_connect``.  ``connect`` is the only required function. The call to
this function is synchronised by the configurator. The ``pre_connect`` and
``post_connect`` functions can preconfigure state and perform actions with
the connections opened by the ``connect`` function without being synchronised
by the configurator. This can help to speed-up release of the semaphores and
complete jobs more efficiently. These actions can also perform data gathering
functions, for example, a traceroute to the host being tested.

Plugins can implement arbitrary functions for the observer function chain.
These track the state of flows and build flow records for different packet
classes: The first chain handles setup on the first packet of a new flow.
Separate chains chains for IP, TCP and UDP packets to allow different
behaviours based on the IP version and transport protocol.

The final plugin function is the merger function. This takes
a job record from a worker and a flow record from the observer and merges the
records before passing the merged record back to PATHspider.
