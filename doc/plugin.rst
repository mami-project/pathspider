Abstract Spider
===============

PATHspider is written to be extensible and the plugins that included in the
PATHspider distribution are only examples of the measurements that PATHspider
can perform.

In order to write your own plugins for PATHspider, you will need to be familiar
with the abstract Spider in :class:`pathspider.base.Spider` and each of the
functions that it performs. The exact specification of plugins is defined in
the :class:`pathspider.base.ISpider` class.

Spider Functionality
--------------------

.. autoclass:: pathspider.base.Spider
   :members:

Spider Interface
----------------

PATHspider will expect the following functions and attributes to be available
in any plugin:

.. autointerface:: pathspider.base.ISpider
    :members:

