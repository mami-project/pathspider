Common Plugin Features
======================

.. _plugmeta:

Plugin Metadata
---------------

All plugins should contain basic metadata that is used internally within
PATHspider for generating help text and command line options. This takes the
form of class variables that by convention are at the start of the class.

+-------------+-----------------------------------------------+
| Name        | Description                                   |
+=============+===============================================+
| name        | A short name for the plugin used in the       |
|             | command line invocation of PATHspider         |
+-------------+-----------------------------------------------+
| description | A human readable description of the plugin    |
|             | used in help text                             |
+-------------+-----------------------------------------------+
| version     | A version number for the plugin               |
+-------------+-----------------------------------------------+

For example, from the DSCP plugin:

.. code-block:: python

 class DSCP(SynchronizedSpider, PluggableSpider):

     name = "dscp"
     description = "Differentiated Services Codepoints"
     version = "1.0.0"

.. note:: Plugins that ship with PATHspider set version to
          ``pathspider.base.__version__``. This should only be done by plugins
          that are part of the PATHspider distribution as this allows these
          plugins to have the same version as PATHspider, which would be
          useless for 3rd-party plugins that release independently.

Command Line Arguments
----------------------

Depending on the type of plugin, default command line arguments will be added
for your plugin. You can add additional command line arguments by adding
a static method to your plugin named `extra_args()`.

For example, from the DSCP plugin:

.. code-block:: python

 @staticmethod
 def extra_args(parser):
     parser.add_argument(
            "--codepoint",
            type=int,
            choices=range(0, 64),
            default='48',
            metavar="[0-63]",
            help="DSCP codepoint to send (Default: 48)")
