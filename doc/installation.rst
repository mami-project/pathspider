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

virtualenv
----------

.. warning:: PATHspider 2.0 depends on pycurl >= 7.43.0.1, released on the 7th
             December 2017. If you have errors when running PATHspider similar
             to ``AttributeError: module 'pycurl' has no attribute
             'CONNECT_TO'`` then it is most likely the case that your version
             of pycurl is too old.


`virtualenv` is a tool to create isolated Python environments. This allows you
to install the dependencies necessary for PATHspider without having them
conflict with your system libraries used for other applications on the system.

The following instructions assume a Debian GNU/Linux system and may have to be
modified on other systems:

.. code-block:: shell

   sudo apt install libtrace-dev libldns-dev python3-dev python3-virtualenv
   mkdir ~/psenv && cd ~/psenv
   python3 -m virtualenv -p /usr/bin/python3 .
   source bin/activate
   export PATH=$PWD/bin:$PATH
   git clone https://github.com/nevil-brownlee/python-libtrace.git
   pushd python-libtrace && python3 setup.py install && popd
   git clone https://github.com/mami-project/pathspider.git
   pushd pathspider && \
       pip install -r requirements.txt && \
       pip install -r requirements_dev.txt && \
       python3 setup.py develop && popd
   pspdr test

Ensure that all tests have passed before beginning to measure or develop with
PATHspider. To re-enter the virtual environment from another shell session:

.. code-block:: shell

   cd ~/psenv
   source bin/activate
   export PATH=$PWD/bin:$PATH
   pspdr test

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

 pip3 install -r requirements.txt

Unfortunately, `python-libtrace
<https://github.com/nevil-brownlee/python-libtrace>`_ is not available on PyPI
and so must be installed seperately. You will also need to ensure that for both
pycurl and python-libtrace you have the build dependencies available as these
are compiled CPython modules.

If you wish to build the documentation from source or to use the testsuite, and
you are installing your dependencies via pip, you will also need the following
dependencies:

.. code-block:: shell

 pip3 install -r requirements_dev.txt

With the dependencies installed, you can install PATHspider with:

.. code-block:: shell

 python3 setup.py install

cloud-init
----------

The following cloud-config script installs PATHspider globally in the VM. The
default user is `ubuntu`. Include your public key to ssh into the VM.

Customise this to your needs. You may want to change the hostname.

::

    #cloud-config

    # Hostname management
    preserve_hostname: False
    hostname: spider
    fqdn: spider.local

    package_update: true

    package_upgrade: true

    ssh_authorized_keys:
     - ssh-rsa <include your public SSH key here>

    packages:
     - git
     - python3
     - python3-pip
     - python3-setuptools
     - python3-pycurl
     - libtrace-dev
     - libldns-dev

    write_files:
    - content: |
        #!/bin/bash
        export LC_ALL=C
        # Select the stable pathspider release, comment for github clone
        REL=2.0.1

        cd /tmp
        git clone https://github.com/nevil-brownlee/python-libtrace.git
        cd python-libtrace/
          make install-py3
        cd -

        if [ -z "$REL" ]; then
          git clone https://github.com/mami-project/pathspider
        else
          wget -q -O - https://github.com/mami-project/pathspider/archive/$REL.tar.gz | tar -xzvf -
        fi

        if [ -d pathspider ]; then
          cd pathspider # github clone
        else
          cd pathspider-$REL # release
        fi
            pip3 install -r requirements.txt
            python3 setup.py install
        cd -
      path: /root/build-psp.sh
      permissions: 0755

    runcmd:
      - ls -al /root > /install-psp.log
      - /root/build-psp.sh

    # Configure where output will go
    output:
      all: ">> /var/log/cloud-init.log"

    # configure interaction with ssh server
    ssh_svcname: ssh
    ssh_deletekeys: True
    ssh_genkeytypes: ['rsa', 'ecdsa']
