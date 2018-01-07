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

.. toctree::
   :maxdepth: 2

   models.rst
   basics.rst
   common.rst
   sync.rst
   desync.rst
   forge.rst
   chains.rst
