Advanced Usage
==============

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
