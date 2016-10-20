Using PATHspider
================

Usage Overview
--------------

You can run PATHspider from the command line. In order for the Observer to
work, you will need permissions to capture raw packets from the network
interface. If you've installed from apt then either the executable in /usr/bin
will have been setuid or will have filesystem permissions set.

.. note::

 If you're running from the source distribution, you will need to execute
 pathspider as:

 .. code-block:: shell

  # sudo /usr/bin/env PYTHONPATH=. python3 pathspider/run.py [...]

.. code-block:: shell

 # pathspider --help
 usage: pathspider [-h] [-s] [-i INTERFACE] [-w WORKERS] [--input INPUTFILE]
                   [--output OUTPUTFILE] [-v]
                   PLUGIN ...

 Pathspider will spider the paths.

 optional arguments:
   -h, --help            show this help message and exit
   -s, --standalone      run in standalone mode. this is the default mode (and
                         currently the only supported mode). in the future,
                         mplane will be supported as a mode of operation.
   -i INTERFACE, --interface INTERFACE
                         the interface to use for the observer
   -w WORKERS, --workers WORKERS
                         number of workers to use
   --input INPUTFILE     a file containing a list of remote hosts to test, with
                         any accompanying metadata expected by the pathspider
                         test. this file should be formatted as a comma-
                         seperated values file. Defaults to standard input.
   --output OUTPUTFILE   the file to output results data to. Defaults to
                         standard output.
   -v, --verbose         log debug-level output.

 Plugins:
   The following plugins are available for use:

     dscp                DiffServ Codepoints
     tls                 Transport Layer Security
     tfo                 TCP Fast Open
     ecn                 Explicit Congestion Notification
     dnsresolv           DNS resolution for hostnames to IPv4 and v6 addresses

 Spider safely!

Quickstart Example
------------------

You can run a small study using the ECN plugin and the included
``webinput.csv`` file to measure path transparency to ECN for a small selection
of web servers and save the results in ``results.txt``:

.. code-block:: shell

 # pathspider -i eth0 ecn </usr/share/doc/pathspider/examples/webinput.csv >results.txt

.. note::

 If you've not installed PATHspider from apt, you will find the webinput.csv
 example script in the examples folder of the source distribution.
