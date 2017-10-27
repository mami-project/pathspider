# -*- mode: ruby -*-
# vi: set ft=ruby :

$setup_pathspider = <<SCRIPT
export DEBIAN_FRONTEND=noninteractive
echo "deb-src http://ftp.debian.org/debian/ buster main" >> /etc/apt/sources.list
apt-get update
apt-get install -y python3-libtrace python3-sphinx python3-straight.plugin python3-setuptools pylint3 python3-pep8 python3-pyroute2 python3-pip unzip
apt-get build-dep -y python3-pycurl
cd /home/vagrant/pathspider
pip3 install -r requirements.txt
pip3 install -r requirements_dev.txt
wget https://github.com/pycurl/pycurl/archive/8d4cee31c8ffdce556d762f0bbb9a482f288f9b7.zip
unzip 8d4cee31c8ffdce556d762f0bbb9a482f288f9b7
cd pycurl-8d4cee31c8ffdce556d762f0bbb9a482f288f9b7/
make
python3 setup.py install
cd ..
rm -rf pycurl-8d4cee31c8ffdce556d762f0bbb9a482f288f9b7/
python3 setup.py develop
SCRIPT

Vagrant.configure("2") do |config|
  # Use Debian jessie
  config.vm.box = "debian/testing64"

  config.vm.define "spider" do |spider|
    spider.vm.synced_folder ".", "/home/vagrant/pathspider"
    spider.vm.provision :shell, :inline => $setup_pathspider
  end

end
