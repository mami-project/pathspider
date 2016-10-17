Using PATHspider
================

Dependencies
------------

PATHspider is a command line tool. If you have installed PATHspider from a
package manager (e.g. apt or pip), you will already have all the dependencies
you need installed.

If you are working from the source distribution (e.g. cloned git repository)
then you will need to install some dependencies. On Debian GNU/Linux:

.. code-block:: shell

 # sudo apt install python3-libtrace python3-straight.plugin python3-dnspython

On other platforms, you may install the dependencies required via pip:

.. code-block:: shell

 # pip install -r requirements.txt

In order to build the documentation from source or to use the testsuite, you
will also need the following dependencies:

.. code-block:: shell

 # sudo apt install python3-sphinx python3-coverage pylint3

Or from pip:

.. code-block:: shell

 # pip install -r requirements-dev.txt

Usage
-----

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

Example
-------

You can run a small study using the ECN plugin and the included `webinput.csv` file
to measure path transparency to ECN for a small selection of web servers:

.. code-block:: shell

 # pathspider -i eth0 ecn <examples/webinput.csv >/tmp/results.txt

.. note::

 The location of the example input file may be different if you've installed
 pathspider from a package manager. On Debian systems it is installed as
 `/usr/share/doc/pathspider/examples/webinput.csv`.

Using Vagrant
-------------

On systems other than Linux systems, you may use Vagrant to run PATHspider.
This may also be useful during development. A Vagrantfile is provided that
will create a Debian-based virtual machine with all the PATHspider dependencies
installed.

In the virtual machine, the PATHspider code will be mounted at
/home/vagrant/pathspider and changes made inside or outside the VM will appear
in both places. PATHspider is installed in development mode, meaning that
this is also the location of the PATHspider code that will be run when
running the /usr/bin/pathspider binary.
