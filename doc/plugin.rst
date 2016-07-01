Writing a plugin
================

PATHspider is written to be extensible and the plugins that included in the
PATHspider distribution are only examples of the measurements that PATHspider
can perform.

The exact specification of plugins is defined in
:class:`pathspider.base.ISpider`, though much of the functionality
required is implemented by the abstract :class:`pathspider.base.Spider` class
which plugins should inherit.

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

.. automethod:: ecnspider3.ECNSpider.config_zero

.. automethod:: ecnspider3.ECNSpider.config_one

(Pre-,Post-)Connection
^^^^^^^^^^^^^^^^^^^^^^

The pre-connection function will run only once, and the result of the
pre-connection operation will be available to both runs of the connection and
post-connection functions.

If you require to pass different values depending on the configuration, you can
perform two operations in the pre-connect function, returning a tuple, and
selecting the value to use based on the configuration in the later functions.

An example implementation of these methods can be found in `ecnspider3`:

.. automethod:: ecnspider3.ECNSpider.connect

.. automethod:: ecnspider3.ECNSpider.post_connect

Merging
^^^^^^^

The merge function will be called for every job and given the job record and
the observer record. The merge function is then to return the final record
to be recorded in the dataset for the measurement run.

.. warning:: It is possible for the Observer to return a NO_FLOW object in
             some circumstances, where the flow has not been observed. Any
             implementation must handle this gracefully.

An example implementation of this method can be found in `ecnspider3`:

.. automethod:: ecnspider3.ECNSpider.merge

Plugin Template
---------------

A template plugin is available in the plugins that ship with the PATHspider
distribution:

.. autoclass:: templatespider.TemplateSpider

ISpider Interface
-----------------

PATHspider will expect the following functions and attributes to be available
in any plugin:

.. autointerface:: pathspider.base.ISpider
    :members:

