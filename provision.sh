#!/bin/bash
# Fail fast on errors
set -euo pipefail

journalctl -u cloud-init --no-pager > /var/log/cloud-init.log
systemctl status ssh --no-pager > /var/log/ssh-status.log

# Network check
ping -c 4 google.com || { echo "No network!"; exit 1; }

# System setup
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# Install build dependencies
apt-get install -y --no-install-recommends \
    git build-essential cmake libpng-dev libtiff-dev \
    libssl-dev libxml2-dev libicu-dev zlib1g-dev \
    libwrap0-dev libjpeg-dev libcharls-dev

# Install runtime dependencies
apt-get install -y \
    python3 python3-pip virtualbox-guest-utils

# DCMTK vulnerable version install
git clone https://github.com/DCMTK/dcmtk.git
cd dcmtk
git checkout 59f75a8  # Vulnerable version
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/usr ..
make -j$(nproc)
make install

# CTF Challenge Setup
# Create flag
echo "HTB{b0f_t0_r00t_v1a_dcmtk}" | sudo tee /root/flag.txt
chmod 600 /root/flag.txt

# Vulnerable service config
cat <<EOF | sudo tee /etc/dcmtk/dcmqrscp.cfg
[global]
  NetworkTCPPort = 11112
  AEtitle = CTF_SERVER
  MaxPDULength = 16384
  OnCrash = /usr/bin/expose_flag.sh
EOF

# SUID binary exploit
cat <<EOF | sudo tee /usr/bin/vuln_dicom_handler.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    if (access("/tmp/exploit_trigger", F_OK) == 0) {
        setuid(0);
        system("/bin/cat /root/flag.txt");
    } else {
        printf("Processing DICOM...\\n");
    }
    return 0;
}
EOF

sudo gcc -o /usr/bin/vuln_dicom_handler /usr/bin/vuln_dicom_handler.c
sudo rm /usr/bin/vuln_dicom_handler.c
sudo chown root:root /usr/bin/vuln_dicom_handler
sudo chmod 4755 /usr/bin/vuln_dicom_handler

# Crash handler script
cat <<EOF | sudo tee /usr/bin/expose_flag.sh
#!/bin/bash
touch /tmp/exploit_trigger
chmod 666 /tmp/exploit_trigger
/usr/bin/vuln_dicom_handler | tee /var/log/flag_exposed.log
EOF
sudo chmod +x /usr/bin/expose_flag.sh

# Final checks
if [ ! -x "/usr/bin/storescp" ]; then
    echo "DCMTK installation failed!" >&2
    exit 1
fi

echo "Provisioning completed successfully"
