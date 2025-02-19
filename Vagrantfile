Vagrant.configure("2") do |config|  
    # ---- DICOM Server (Machine A) ----  
  config.vm.define "dicom" do |dicom|  
    dicom.vm.box = "ubuntu/jammy64"  
    dicom.vm.hostname = "dicom.htb"  
    # Internal network for inter-VM communication  
    dicom.vm.network "private_network", ip: "192.168.56.10", 
      virtualbox__intnet: "htb-internal"  
    # Provision with Ansible  
    dicom.vm.provision "ansible" do |ansible|  
      ansible.playbook = "ansible/playbook-a.yml"  
      ansible.compatibility_mode = "2.0"  
    end  
  end  

  # ---- PACS Server (Machine B) ----  
  config.vm.define "pacs" do |pacs|  
    pacs.vm.box = "generic/alpine38"  
    pacs.vm.hostname = "pacs.htb"  
    pacs.vm.network "private_network", ip: "192.168.56.20",  
      virtualbox__intnet: "htb-internal"  
    pacs.vm.provision "ansible" do |ansible|  
      ansible.playbook = "ansible/playbook-b.yml"  
      ansible.compatibility_mode = "2.0"  
    end  
  end  
  # Post-creation message
  config.vm.post_up_message = <<-MESSAGE
  [+] DICOM CTF Challenge Ready!
  [+] Connect to: storescp://127.0.0.1:11112
  [+] Use AE Title: CTF_SERVER
  MESSAGE
end

