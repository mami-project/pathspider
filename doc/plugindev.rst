Developing Plugins
==================

PATHspider is written to be extensible and the plugins that are included in the
PATHspider distribution are examples of the measurements that PATHspider can
perform.

:mod:`pathspider.plugins` is a namespace package. Namespace packages are a
mechanism for splitting a single Python package across multiple directories on
disk. One or more distributions may provide modules which exist inside the same
namespace package. The PATHspider distribution's plugins are installed in
:mod:`pathspider.plugins`, but also 3rd-party plugins can exist in this path
without being a part of the PATHspider distribution.

Quickstart
----------

The directory layout and example plugin below can be found in the
`pathspider-example GitHub repository
<https://github.com/mami-project/pathspider-example/>`_. You can get going
quickly by forking this repository and using that as a basis for plugin
development.

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

Example Plugin
--------------

The following code can be found in the quickstart example as a starting point
for developing your plugin. If you are not using the quickstart example, you
may copy and paste this code into a Python file under ``pathspider/plugins/``
in the directory structure. This example is explained in the following
sections.

.. code-block:: python

 import sys
 import collections
 import logging

 from pathspider.base import SynchronizedSpider
 from pathspider.base import PluggableSpider
 from pathspider.base import CONN_OK, CONN_TIMEOUT, CONN_FAILED

 from pathspider.observer import simple_observer

 class Example(SynchronizedSpider, PluggableSpider):
     """
     An example PATHspider plugin.
     """

     def config_zero(self):
         logger = logging.getLogger("example")
         logger.debug("Configuration zero")

     def config_one(self):
         logger = logging.getLogger("example")
         logger.debug("Configuration one")

     def connect(self, job, config):
         return self.tcp_connect(job)

     def post_connect(self, job, rec, config):
         try:
             rec['client'].shutdown(socket.SHUT_RDWR)
         except:
             pass

         try:
             rec['client'].close()
         except:
             pass

         # The client is no longer usable, don't leave it in the spider record
         rec.pop('client')

     def create_observer(self):
         logger = logging.getLogger("example")
         try:
             return simple_observer()
         except:
             logger.error("Observer would not start")
             sys.exit(-1)

     @staticmethod
     def register_args(subparsers):
         parser = subparsers.add_parser('example', help="Example starting point for development")
         parser.set_defaults(spider=Example)


You will need to provide implementations for each of these functions, which
are explained next. We'll start with the connection logic.

Connection Logic
----------------

Configurator
^^^^^^^^^^^^

These functions perform global changes that may be required between performing
the baseline (A) and the experimental (B) configurations. The changes may
be a call to sysctl, changes via netfilter or a call to a robot arm to
reposition the satellite array. In the event that global state changes are
not required, these can be implemented as no-ops.

An example implementation of these methods can be found in the ECN plugin:

.. automethod:: pathspider.plugins.ecn.ECN.config_zero

.. automethod:: pathspider.plugins.ecn.ECN.config_one

(Pre-,Post-) Connection
^^^^^^^^^^^^^^^^^^^^^^^

The pre-connection function will run only once, and the result of the
pre-connection operation will be available to both runs of the connection and
post-connection functions.

If you require to pass different values depending on the configuration, you can
perform two operations in the pre-connect function, returning a tuple, and
selecting the value to use based on the configuration in the later functions.

An example implementation of these methods can be found in the ECN plugin:

.. automethod:: pathspider.plugins.ecn.ECN.connect

.. automethod:: pathspider.plugins.ecn.ECN.post_connect


Observer Functions
------------------

PATHspider's observer will accept functions and pass `python-libtrace
<https://www.cs.auckland.ac.nz/~nevil/python-libtrace/>`_ dissected packets
along with the associated flow record to them for every packet recieved.

The :mod:`pathspider.observer` module provides
:func:`pathspider.observer.simple_observer` which allows the creation of a very
simple Observer during development of the other portions of the plugin. There
are two simple examples of observer functions that are used in the observer
created by this function.

When you are ready to start working with your own Observer functions, you will
need to expand your ``create_observer()`` function. You can use the following
example:

.. code-block:: python

 from pathspider.observer import Observer
 from pathspider.observer import basic_flow
 from pathspider.observer import basic_count

 class Example(SynchronizedSpider, PluggableSpider):

     [...]

     def create_observer(self):
         logger = logging.getLogger("example")
         try:
             return Observer(self.libtrace_uri,
                             new_flow_chain=[basic_flow],
                             ip4_chain=[basic_count],
                             ip6_chain=[basic_count])
         except:
             logger.error("Observer would not start")
             sys.exit(-1)

Depending on the types of analysis you would like to do on the packets, you
should pass your functions to the appropriate chain:

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

Library Observer Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^

The :func:`pathspider.observer.basic_flow` function simply creates the inital
state for the flow record, extracting the 5-tuple and initialising counters.
The counters are used by the :func:`pathspider.observer.basic_count` function
that counts the number of packets and octets seen in each direction. These
combined will allow your plugin to produce the :ref:`default output fields
<defaultoutput>`.

PATHspider also provides library observer functions for some protocols:

.. toctree::
   :glob:
   :titlesonly:

   plugindev/*

Writing Observer Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^

When you are ready to write functions for the observer, first identify which
data should be stored in the flow record. This is a :class:`dict` that is made
available for every call to an observer function for a particular flow and
not shared across flows.

The flow record should be initialised when a new flow has been identified. The
functions in the ``new_flow_chain`` are called, in sequence, when a new flow
is identified by the Observer. These functions are passed two arguments:
``rec`` - the empty flow record, and ``ip`` - the IP header.

You should familiarise yourself with the `python-libtrace documentation
<https://www.cs.auckland.ac.nz/~nevil/python-libtrace/>`_. The analysis
functions all follow the same function prototype with ``rec`` - the empty flow
record, ``x`` - the header, and ``rev`` - boolean value indicating the
direction the packet travelled (i.e. Was the packet in the reverse direction?).

The only difference in these functions is the header that is passed, as a
python-libtrace object, to the function. The same flow record is always passed
for each call for the same flow, regardless of which function chain the
function is in.

If a function returns False, as it has identified the end of the flow, the
Observer will consider the flow to be finished and will pass it to be merged
with the job record after a short delay. This might occur for TCP flows when
both FIN packets have been seen using the
:func:`pathspider.observer.tcp.tcp_state` function.

Running Your Plugin
-------------------

In order to run your plugin, in the root of your plugin source tree run:

.. code-block:: shell

 PYTHONPATH=. pathspider example </usr/share/doc/pathspider/examples.csv >results.txt

Unless you install your plugin, you will need to add the plugin tree to the
``PYTHONPATH`` to allow the plugin to be discovered.
