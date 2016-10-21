Developing Plugins
==================

PATHspider is written to be extensible and the plugins that included in the
PATHspider distribution are only examples of the measurements that PATHspider
can perform.

:mod:`pathspider.plugins` is a namespace package. Namespace packages are a
mechanism for splitting a single Python package across multiple directories on
disk. One or more distributions may provide modules which exist inside the same
namespace package. The PATHspider distribution's plugins are installed here,
but also 3rd-party plugins can exist in this path without being a part of the
PATHspider distribution.

Directory Layout
----------------

To get started you will need to create the required directory layout for
PATHspider plugins, in this case for the Example plugin::

 pathspider-example
 └── pathspider
     ├── __init__.py
     └── plugins
         ├── __init__.py
         └── example.py

Inside both __init__.py files, you will need to add the following (and only
the following):

.. code-block:: python

 from pkgutil import extend_path
 __path__ = extend_path(__path__, __name__)

Your plugin will be written in ``example.py`` and this plugin will be
discovered automatically when you run PATHspider.

An Example Plugin
-----------------

.. code-block:: python

 import sys
 import collections
 import logging
 
 from pathspider.base import SynchronizedSpider
 from pathspider.base import PluggableSpider
 from pathspider.base import NO_FLOW
 
 from pathspider.observer import Observer
 from pathspider.observer import basic_flow
 from pathspider.observer import basic_count
 
 Connection = collections.namedtuple("Connection", ["host", "state"])
 SpiderRecord = collections.namedtuple("SpiderRecord", ["ip", "rport", "port",
                                                        "host", "config",
                                                        "connstate"])
 
 class Template(SynchronizedSpider, PluggableSpider):
 
     """
     A template PATHspider plugin.
     """
 
     def config_zero(self):
         logger = logging.getLogger("template")
         logger.debug("Configuration zero")
 
     def config_one(self):
         logger = logging.getLogger("template")
         logger.debug("Configuration one")
 
     def connect(self, job, pcs, config):
         sock = "Hello"
         return Connection(sock, 1)
 
     def post_connect(self, job, conn, pcs, config):
         rec = SpiderRecord(job[0], job[1], job[2], config, True)
         return rec
 
     def create_observer(self):
         logger = logging.getLogger("template")
         try:
             return Observer(self.libtrace_uri,
                             new_flow_chain=[basic_flow],
                             ip4_chain=[basic_count],
                             ip6_chain=[basic_count])
         except:
             logger.error("Observer would not start")
             sys.exit(-1)
 
     def merge(self, flow, res):
         if flow == NO_FLOW:
             flow = {"dip": res.ip,
                     "sp": res.port,
                     "dp": res.rport,
                     "observed": False}
         else:
             flow['observed'] = True
 
         self.outqueue.put(flow)
 
     @staticmethod
     def register_args(subparsers):
         parser = subparsers.add_parser('template', help="Template for development")
         parser.set_defaults(spider=Template)
 
Required Functions
------------------

In order to write a plugin you will need to produce implementations for the
following: :func:`config_zero <ISpider.config_zero>`, :func:`config_one
<ISpider.config_one>`, :func:`connect <ISpider.connect>` and :func:`merge
<ISpider.merge>`.

Optionally, you can provide :func:`pre_connect <ISpider.pre_connect>` and
:func:`post_connect <ISpider.post_connect>`.

Configurator
^^^^^^^^^^^^

These functions perform global changes that may be required between performing
the baseline (A) and the experimental (B) configurations. The changes may
be a call to sysctl, changes via netfilter or a call to a robot arm to
reposition the satellite array. In the event that global state changes are
not required, these can be implemented as no-ops.

An example implementation of these methods can be found in `ecnspider3`:

.. automethod:: ecn.ECN.config_zero

.. automethod:: ecn.ECN.config_one

(Pre-,Post-)Connection
^^^^^^^^^^^^^^^^^^^^^^

The pre-connection function will run only once, and the result of the
pre-connection operation will be available to both runs of the connection and
post-connection functions.

If you require to pass different values depending on the configuration, you can
perform two operations in the pre-connect function, returning a tuple, and
selecting the value to use based on the configuration in the later functions.

An example implementation of these methods can be found in `ecnspider3`:

.. automethod:: ecn.ECN.connect

.. automethod:: ecn.ECN.post_connect

Merging
^^^^^^^

The merge function will be called for every job and given the job record and
the observer record. The merge function is then to return the final record
to be recorded in the dataset for the measurement run.

.. warning:: It is possible for the Observer to return a NO_FLOW object in
             some circumstances, where the flow has not been observed. Any
             implementation must handle this gracefully.

An example implementation of this method can be found in `ecnspider3`:

.. automethod:: ecn.ECN.merge

Plugin Template
---------------

A template plugin is available in the plugins that ship with the PATHspider
distribution:

.. autoclass:: template.Template

.. _observer:

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

