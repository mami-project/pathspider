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

Configurator
~~~~~~~~~~~~

(Pre-,Post-)Connection
~~~~~~~~~~~~~~~~~~~~~~

Merging
~~~~~~~

.. warning:: Null flows


ISpider Interface
-----------------

PATHspider will expect the following functions and attributes to be available
in any plugin:

.. autointerface:: pathspider.base.ISpider
    :members:

