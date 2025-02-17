source "qemu" "dcmtk-ctf" {
  iso_url          = "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  iso_checksum     = "sha256:5b6d6e4a73b40c2189d3ec3a43e52c5f4f9c3355e4b0f8e705a3b99b59e5a9b7"
  ssh_username     = "ubuntu"
  disk_size        = "8G"
  memory           = 2048
  output_directory = "output"
}

build {
  sources = ["source.qemu.dcmtk-ctf"]

  provisioner "shell" {
    script = "provision.sh"
  }

  post-processor "vagrant" {
    output = "dcmtk-ctf.box"
  }
}