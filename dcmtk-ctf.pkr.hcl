source "virtualbox-iso" "dcmtk-ctf" {
  iso_url          = "https://releases.ubuntu.com/releases/22.04.4/ubuntu-22.04.5-live-server-amd64.iso"
  iso_checksum     = "sha256:9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"
  guest_os_type    = "Ubuntu_64"
  ssh_username     = "vagrant"
  ssh_password     = "vagrant"
  ssh_timeout      = "30m"
  shutdown_command = "echo 'vagrant' | sudo -S shutdown -P now"
  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--memory", "2048"],
    ["modifyvm", "{{.Name}}", "--cpus", "2"]
  ]
}

build {
  sources = ["source.virtualbox-iso.dcmtk-ctf"]

  provisioner "shell" {
    script = "provision.sh"
  }

  post-processor "vagrant" {
    output = "dcmtk-ctf.box"
  }
}

packer {
  required_plugins {
    vagrant = {
      version = ">= 1.0.3"
      source  = "github.com/hashicorp/vagrant"
    }
  }
    required_plugins {
      virtualbox = {
        version = "~> 1"
        source  = "github.com/hashicorp/virtualbox"
      }
  }
}