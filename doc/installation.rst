Installation
============

Debian GNU/Linux
----------------

.. note:: If there has not been much time since the release, the Debian
          packages for the latest version may not yet be available.

PATHspider is packaged for Debian and packages are made available for the
testing and stable-backports distributions. If you are running Debian stable,
ensure that you have `enabled the stable-backports repository
<https://backports.debian.org/Instructions/>`_ in your apt sources.

To install PATHspider, simply run:

.. code-block:: shell

  sudo apt install pathspider

Vagrant
-------

.. warning:: Depending on the set up of your Vagrant virtualization provider,
             some tests may be affected. It is wise to test against known
             configurations to ensure that your networking set up has a clear
             path to the Internet before running larger measurement campaigns.

On systems other than Linux systems, you may use `Vagrant
<https://www.vagrantup.com/>`_ to run PATHspider.  This may also be useful
during development. A Vagrantfile is provided that will create a Debian-based
virtual machine with all the PATHspider dependencies installed.

In the virtual machine, the PATHspider code will be copied to
``/vagrant``. To improve compatibility across platforms, this
is not synchronized with the repository outside of the Vagrant image. Expert
users may edit the ``Vagrantfile`` to achieve this. PATHspider is installed in
development mode, meaning that this is also the location of the PATHspider code
that will be run when running the ``/usr/bin/pspdr`` command inside the virtual
machine.

Assuming that you have Vagrant and a virtualisation provider (e.g. VirtualBox)
installed, you can get started with:

.. code-block:: shell

   vagrant up
   vagrant ssh

Depending on the speed of your Internet connection, this may take a long time.

Source
------

.. warning:: PATHspider 2.0 depends on pycurl >= 7.43.0.1, released on the 7th
             December 2017. If you have errors when running PATHspider similar
             to ``AttributeError: module 'pycurl' has no attribute
             'CONNECT_TO'`` then it is most likely the case that your version
             of pycurl is too old.

If you are working from the source distribution (e.g. cloned git repository)
then you will need to install the required dependencies. On Debian GNU/Linux,
assuming you have the stable-backports repository enabled if you are running
stable:

.. code-block:: shell

  sudo apt build-dep pathspider

.. note:: This will install both the runtime and the build dependencies required
          for PATHspider, its testsuite and its documentation.

On other platforms, you may install most of the dependencies required via pip:

.. code-block:: shell

 pip install -r requirements.txt

Unfortunately, `python-libtrace
<https://github.com/nevil-brownlee/python-libtrace>`_ is not available on PyPI
and so must be installed seperately. You will also need to ensure that for both
pycurl and python-libtrace you have the build dependencies available as these
are compiled CPython modules.

If you wish to build the documentation from source or to use the testsuite, and
you are installing your dependencies via pip, you will also need the following
dependencies:

.. code-block:: shell

 pip install -r requirements_dev.txt

With the dependencies installed, you can install PATHspider with:

.. code-block:: shell

 python3 setup.py install
