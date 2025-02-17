source "virtualbox-ovf" "dcmtk-ctf" {
  ova_url          = "https://cloud-images.ubuntu.com/releases/24.04/release-20250211/ubuntu-24.04-server-cloudimg-amd64.ova"
  ova_checksum     = "sha256:8c9f3dd1d04d4e0d09a7b62a1de8173ea8b45420915490e219d710ed4c6fdcdc"
  headless     = true
  ssh_username = "ubuntu"
  ssh_password = "ubuntu"
  ssh_timeout      = "30m"
  
  vboxmanage_post = [
    ["modifyvm", "{{.Name}}", "--natpf1", "guestssh,tcp,,2222,,22"]
  ]

  boot_command = [
    "<enter><wait>",
    "linux /casper/vmlinuz autoinstall ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/<wait>",
    "<enter>"
  ]
  
  http_directory = "http"
}

build {
  sources = ["source.virtualbox-ova.dcmtk-ctf"]

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
      version = ">= 1.1.4"
      source  = "github.com/hashicorp/vagrant"
    }
  }
    required_plugins {
      virtualbox = {
        version = ">= 1.0.6"
        source  = "github.com/hashicorp/virtualbox"
      }
  }
}