Plugin Basics
=============

Quickstart
----------

The directory layout and example plugin below can be found in the
`pathspider-example GitHub repository
<https://github.com/mami-project/pathspider-example/>`_. You can get going
quickly by forking this repository and using that as a basis for plugin
development. The repository has templates for a Synchronized, a Desynchronized
and a Forge plugin.

Directory Layout
----------------

:mod:`pathspider.plugins` is a namespace package. Namespace packages are a
mechanism for splitting a single Python package across multiple directories on
disk. One or more distributions may provide modules which exist inside the same
namespace package. The PATHspider distribution's plugins are installed in
:mod:`pathspider.plugins`, but also 3rd-party plugins can exist in this path
without being a part of the PATHspider distribution.

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

Running Your Plugin
-------------------

In order to run your plugin, in the root of your plugin source tree run:

.. code-block:: shell

 PYTHONPATH=. pspdr measure -i eth0 example </usr/share/doc/pathspider/examples/webtest.ndjson

Unless you install your plugin, you will need to add the plugin tree to the
``PYTHONPATH`` to allow the plugin to be discovered.
