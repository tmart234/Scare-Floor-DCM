Vagrant.configure("2") do |config|
    config.vm.box = "dcmtk-ctf"
    config.vm.box_url = "file://dcmtk-ctf.box"
    
    config.vm.network "forwarded_port", guest: 11112, host: 11112
    
    config.vm.provider "virtualbox" do |vb|
      vb.memory = 2048
    end
  
    config.vm.provision "shell", inline: <<-SHELL
      nohup storescp --verbose --fork --promiscuous \
        --aetitle TEST_AE \
        --output-directory /var/dicom/storage \
        --port 11112 > /var/log/dcmtk.log 2>&1 &
    SHELL
  end