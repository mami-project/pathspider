# -*- mode: ruby -*-
# vi: set ft=ruby :

$setup_pathspider = <<SCRIPT
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-libtrace python3-sphinx python3-straight.plugin python3-setuptools pylint3 python3-pep8
cd /home/vagrant/pathspider
pip -r requirements.txt
pip -r requirements-dev.txt
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
