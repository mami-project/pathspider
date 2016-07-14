# -*- mode: ruby -*-
# vi: set ft=ruby :

$setup_pathspider = <<SCRIPT
echo "deb http://ftp.de.debian.org/debian/ testing main" >> /etc/apt/sources.list
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-libtrace python3-sphinx python3-straight.plugin python3-setuptools
cd /data/pathspider
python3 setup.py develop
SCRIPT

Vagrant.configure("2") do |config|
  # Use Debian jessie
  config.vm.box = "debian/contrib-jessie64"

  config.vm.define "spider" do |spider|
    spider.vm.synced_folder ".", "/data/pathspider"
    spider.vm.provision :shell, :inline => $setup_pathspider
  end

end
