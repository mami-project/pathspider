Using PATHspider
================

Quickstart
----------

Dependencies
~~~~~~~~~~~~

PATHspider is a command line tool. If you have installed PATHspider from a
package manager (e.g. apt or pip), you will already have all the dependencies
you need installed.

If you are working from the source distribution (e.g. cloned git repository)
then you will need to install some dependencies. On Debian GNU/Linux:

.. code-block:: shell

 # sudo apt install python3-libtrace python3-straight.plugin

In order to build the documentation from source, you will also need the
following dependencies:

.. code-block:: shell 
 
 # sudo apt install python3-sphinx

Usage
~~~~~

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

 # pathspider -h
 usage: run.py [-h] [-s] [-l] [-p PLUGIN] [-i INTERFACE] [-w WORKER_COUNT]
               INPUTFILE OUTPUTFILE
 
 Pathspider will spider the paths.
 
 positional arguments:
   INPUTFILE             a file containing a list of remote hosts to test, with
                         any accompanying metadata expected by the pathspider
                         test. this file should be formatted as a comma-
                         seperated values file.
   OUTPUTFILE            the file to output results data to
 
 optional arguments:
   -h, --help            show this help message and exit
   -s, --standalone      run in standalone mode. this is the default mode (and
                         currently the only supported mode). in the future,
                         mplane will be supported as a mode of operation.
   -l, --list-plugins    print the list of installed plugins
   -p PLUGIN, --plugin PLUGIN
                         use named plugin
   -i INTERFACE, --interface INTERFACE
                         the interface to use for the observer
   -w WORKER_COUNT, --worker-count WORKER_COUNT
                         number of workers to use

Example
~~~~~~~

You can run a small study using ECNSpider and the included `webinput.csv` file
to measure path transparency to ECN for a small selection of web servers:

.. code-block:: shell

 # pathspider -i eth0 -w 10 examples/webinput.csv /tmp/results.txt

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
