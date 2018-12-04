# -*- mode: ruby -*-
# vi: set ft=ruby :

$setup_pathspider = <<SCRIPT
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt install -y libtrace-dev libldns-dev python3-dev python3-pip git
git clone https://github.com/nevil-brownlee/python-libtrace.git
pushd python-libtrace && python3 setup.py install && popd
pushd /vagrant && \
    pip3 install -r requirements.txt && \
    pip3 install -r requirements_dev.txt && \
    python3 setup.py develop && popd
pspdr test
SCRIPT

Vagrant.configure("2") do |config|
  # Use Debian buster
  config.vm.box = "debian/testing64"

  config.vm.define "spider" do |spider|
    spider.vm.provision :shell, :inline => $setup_pathspider
  end

end
