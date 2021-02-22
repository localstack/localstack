# -*- mode: ruby -*-
# vi: set ft=ruby :

if !Vagrant.has_plugin?('vagrant-vbguest')
	puts 'vagrant-vbguest plugin required. Run `vagrant plugin install vagrant-vbguest` to install'
	abort
end

Vagrant.configure("2") do |config|
  config.vm.box = "centos/8"
  config.vm.box_version = "1905.1"

  config.vm.provision "shell", inline: <<-SHELL
    sudo yum install python3 python3-devel -y
    sudo yum install cyrus-sasl-devel -y

    sudo yum install -y yum-utils net-tools telnet
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo yum install -y docker-ce docker-ce-cli containerd.io
    sudo chkconfig docker on
    sudo service docker start

    sudo ln -s /usr/bin/python3 /usr/bin/python
    sudo ln -s /usr/bin/pip3.6 /usr/bin/pip

    docker pull localstack/localstack

    cd /localstack
    sudo make install

  SHELL
  config.vm.synced_folder ".", "/localstack", type: "nfs"
  config.vm.network "private_network", type: "dhcp"
end
