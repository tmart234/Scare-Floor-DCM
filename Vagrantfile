config.vm.post_up_message = "DCMTK CTF Ready on port 11112"
config.vm.define_checkpoint do |checkpoint|
  checkpoint.name = "pre_provision_state"
  checkpoint.action :snapshot
end

Vagrant.configure("2") do |config|
    config.vm.box = "dcmtk-ctf"
    config.vm.box_url = "file://dcmtk-ctf.box"
    
    config.vm.network "forwarded_port", guest: 11112, host: 11112
    
    config.vm.provider "virtualbox" do |vb|
      vb.memory = 2048
      vb.cpus = 2
      vb.customize ["modifyvm", :id, "--ioapic", "on"]
    end
  
    config.vm.provision "shell", inline: <<-SHELL
      nohup storescp --verbose --fork --promiscuous \
        --aetitle TEST_AE \
        --output-directory /var/dicom/storage \
        --port 11112 > /var/log/dcmtk.log 2>&1 &
    SHELL
  end