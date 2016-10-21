Advanced Topics
===============

PATHspider Internals
--------------------

To learn more about the internals of PATHspider, you can read the following
pages describing the operation of individual parts of the architecture:

.. toctree::
   :glob:
   :titlesonly:

   internals/*

PATHspider on Vagrant
---------------------

On systems other than Linux systems, you may use Vagrant to run PATHspider.
This may also be useful during development. A Vagrantfile is provided that
will create a Debian-based virtual machine with all the PATHspider dependencies
installed.

In the virtual machine, the PATHspider code will be mounted at
`/home/vagrant/pathspider` and changes made inside or outside the VM will appear
in both places. PATHspider is installed in development mode, meaning that
this is also the location of the PATHspider code that will be run when
running the `/usr/bin/pathspider` binary.

PATHspider on MONROE
--------------------

PATHspider provides a Docker container that may be extended by experimenters
using the `MONROE testbed <https://www.monroe-project.eu/>`_. You can read
more about how to use PATHspider on MONROE in the `project's README
<https://github.com/mami-project/pathspider-monroe/blob/master/README.md>`_.
