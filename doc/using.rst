Command Line Usage Overview
===========================

You can run PATHspider from the command line. In order for the Observer to
work, you will need permissions to capture raw packets from the network
interface. You may also need elevated privileges when generating traffic using
raw sockets or to modify the local TCP/IP stack. This will require you to use
``sudo`` or equivalent in order to run PATHspider if you are not logged in as
the root user.

.. code-block:: text

 # pspdr --help
 usage: pspdr [-h] [--verbose] COMMAND ...

 PATHspider will spider the paths.

 optional arguments:
   -h, --help  show this help message and exit
   --verbose   Enable verbose logging

 Commands:
     filter    Pre-process a target list
     measure   Perform a PATHspider measurement
     observe   Passively observe network traffic
     test      Run the built in test suite

 Spider safely!

Performing Active Measurement
-----------------------------

PATHspider provides the "measure" command to perform active traffic generation
and observation of that traffic for path transparency measurement. Based on
the observations made, paths are assigned conditions such as
`ecn.connectivity.works` indicating that the use of ECN does not cause
connectivity impairment between the vantage point and the particular target.

It is possible to enable the output of flow records along with the derived
observations using the ``--output-flows`` flag. This will generate considerably
more output and so is disabled by default.

You may specify input and output files using flags, however by default these
are set to be stdin and stdout and so you can, and are recommended to, use
shell redirection instead.

You will be required to set your interface name and PATHspider will not start
if it detects that the chosen interface is not active.

.. code-block:: text

 # pspdr measure --help
 usage: pspdr measure [-h] [-i INTERFACE] [-w WORKERS] [--input INPUTFILE]
                     [--output OUTPUTFILE] [--output-flows]
                     PLUGIN ...

 optional arguments:
   -h, --help            show this help message and exit
   -i INTERFACE, --interface INTERFACE
                         The interface to use for the observer. (Default: eth0)
   -w WORKERS, --workers WORKERS
                         Number of workers to use. (Default: 100)
   --input INPUTFILE     A file containing a list of PATHspider jobs. Defaults
                         to standard input.
   --output OUTPUTFILE   The file to output results data to. Defaults to
                         standard output.
   --output-flows        Include flow results in output.

 Plugins:
   The following plugins are available for use:

     tfo                 TCP Fast Open
     ecn                 Explicit Congestion Notification
     h2                  HTTP/2
     dscp                Differentiated Services Codepoints
     dnsresolv           Simple Input List DNS Resolver
     udpopts             UDP Options Trailer
     udpzero             UDP Zero Checksum

 Spider safely!


Quickstart Example
~~~~~~~~~~~~~~~~~~

You can run a small study using the ECN plugin and the included
``webtest.ndjson`` file to measure path transparency to ECN for a small selection
of web servers and save the results in ``results.ndjson`` (ensure to change the
interface name to match an active interface on your machine):

.. code-block:: shell

 pspdr measure -i eth0 ecn </usr/share/doc/pathspider/examples/webtest.ndjson >results.ndjson

.. note::

 If you've not installed PATHspider from apt, you will find the webinput.ndjson
 example input file in the examples folder of the source distribution.

Performing Passive Observation
------------------------------

PATHspider provides the "observe" command to perform passive traffic
observation for path transparency measurement.  In this version of PATHspider
we do not attempt to determine path conditions during passive observation, and
instead only output flow records. This may change in future versions of
PATHspider.

You can list the available chains with ``--list-chains`` and then select any
number of chains that you would like to use. It is recommended that you include
the `basic` chain as this will add the IP addresses and port numbers to the
flow records.

You may specify the output file using a flag, however by default this is set to
be ``/dev/stdout`` and so you can, and are recommended to, use shell
redirection instead. You will be required to set your interface name and
PATHspider will not start if it detects that the chosen interface is not
active.

.. code-block:: text

 usage: pspdr observe [-h] [--list-chains] [-i INTERFACE] [--output OUTPUTFILE]
                      [chains [chains ...]]

 positional arguments:
   chains                Observer chains to use

 optional arguments:
   -h, --help            show this help message and exit
   --list-chains         Prints a list of available chains
   -i INTERFACE, --interface INTERFACE
                         The interface to use for the observer. (Default: eth0)
   --output OUTPUTFILE   The file to output results data to. Defaults to
                         standard output.


Quickstart Example
~~~~~~~~~~~~~~~~~~

You can observe network traffic passively to perform observations without
actively generating traffic. In this case no input file is needed.

.. code-block:: shell

 pspdr observe -i eth0 basic tcp ecn >results.ndjson

Data Formats
------------

PATHspider uses `newline delimited JSON <http://ndjson.org/>`_ (ndjson) for
both the output format when in standalone (the default) mode. The ndjson format
gives flexibility in the actual contents of the data as different tests may
require data to remain associated with jobs, for example the Alexa ranking of a
webserver, so that it can be present in the final output, or in some cases the
data may be used as part of the test, for example when running tests against
authoritative DNS servers and needing to know a domain for which the server
should be authoritative.

.. _defaultoutput:

Input Format
~~~~~~~~~~~~

At a minimum, each job should contain an IP address in a ``dip`` field.
Depending on the plugin in use, more details may be required. Refer to the
documentation for the specific plugin for more information.

Output Format
~~~~~~~~~~~~~

For each job, the output JSON dictionary will contain the original job
information, a computed path using available information and a set of
conditions seen for the path as generated by the plugins.

With ``--output-flows`` enabled, PATHspider's output will include an additional
field in the JSON dictionary for each job containing an array of flow records,
one for each configuration. Usually one record will be for the baseline (A)
connection, and one for the experimental (B) connection. These JSON records
contain the original job information, any information added by the connection
functions and any information added by the Observer.

Additionally, internal information may be retained:

+------------+----------------------------------------------------------------+
| Key        | Description                                                    |
+============+================================================================+
| config     | 0 for baseline, 1..n for experimental                          |
+------------+----------------------------------------------------------------+
| spdr_state | 0 = OK, 1 = TIMEOUT, 2 = FAILED, 3 = SKIPPED                   |
+------------+----------------------------------------------------------------+

For detail on the values in individual plugins, see the section for that plugin
later in this documentation.

