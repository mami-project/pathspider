Abstract Spider
===============

The core functionality of PATHspider plugins is implemented in two classes:
:class:`pathspider.sync.SynchronizedSpider` and
:class:`pathspider.desync.DesynchronizedSpider`. There is also a third class,
:class:`pathspider.forge.ForgeSpider` that inherits from
:class:`pathspider.desync.DesynchronizedSpider`. These both inherit from the
base :class:`pathspider.base.Spider` which provides a skeleton that has the
required functions for any plugin. The documentation for this base class is
below:

pathspider.base
---------------

.. automodule:: pathspider.base
   :members:
   :undoc-members:


