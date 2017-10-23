SynchronizedSpider Development
==============================

SynchronizedSpider plugins use built-in connection methods along with global
system configuration to change the behaviour of the connections.

Connection Modes
----------------

The following connection types are built-in to PATHspider:

+-------------------+-------------------------------------------+
| Name              | Description                               |
+===================+===========================================+
| tcp               | Perform a TCP handshake                   |
+-------------------+-------------------------------------------+
| http              | Perform an HTTP GET request               |
+-------------------+-------------------------------------------+
| https             | Perform an HTTP GET request using TLS     |
+-------------------+-------------------------------------------+
| dnsudp            | Perform a DNS query using UDP             |
+-------------------+-------------------------------------------+
| dnstcp            | Perform a DNS query using TCP             |
+-------------------+-------------------------------------------+

To indicate the connection types that are supported by your plugin,
use the ``connect_supported`` metadata variable. The first type listed
in the variable will be the default connection type for the plugin.

For example, if your plugin supports all the TCP based connection types and you
would like plain HTTP to be the default:

.. code-block:: python

    class SynchronizedSpiderPlugin(SynchronizedSpider, PluggableSpider):
        connect_supported = ["http", "https", "tcp", "dnstcp"]

Configuration Functions
-----------------------

Configuration functions are at the heart of a SynchronizedSpider plugin.
These may make calls to ``sysctl`` or ``iptables`` to make changes to the way
that traffic is generated.

One function should be written for each of the configurations and PATHspider
will ensure that the configurations are set before the corresponding traffic is
generated. It is the responsibility of plugin authors to ensure that any
configuration is reset by the next configuration function if that is
required.

By convention, functions should be prefixed with ``config_`` to ensure there
are no conflicts. After declaring the functions, you must then set the
``configurations`` metadata variable with pointers to each of the configuration
functions.

The following shows the relevant portions of the ECN plugin, which uses this
framework:

.. code-block:: python

    class ECN(SynchronizedSpider, PluggableSpider):
        def config_no_ecn(self): # pylint: disable=no-self-use
            """
            Disables ECN negotiation via sysctl.
            """
    
            logger = logging.getLogger('ecn')
            subprocess.check_call(
                ['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=2'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            logger.debug("Configurator disabled ECN")
    
        def config_ecn(self): # pylint: disable=no-self-use
            """
            Enables ECN negotiation via sysctl.
            """
    
            logger = logging.getLogger('ecn')
            subprocess.check_call(
                ['/sbin/sysctl', '-w', 'net.ipv4.tcp_ecn=1'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            logger.debug("Configurator enabled ECN")
    
        configurations = [config_no_ecn, config_ecn]

.. warning:: You must have the ``configurations`` variable *after* the declaration of
             the functions, as otherwise you are attempting to reference functions that
             have not yet been defined.
