#!/bin/bash
# called by packer .hcl
# Aim for minimal setup (<100MB install footprint)
apt-get update
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip

pip3 install --no-cache-dir scapy boofuzz

mkdir -p /var/dicom/storage
chmod 777 /var/dicom/storage

# DCMTK install
git clone https://github.com/DCMTK/dcmtk.git
cd dcmtk
git checkout 59f75a8 # vulnerable v3.6.8
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF ..
make -j$(nproc)
sudo make install

# Create flag accessible only via exploit
echo "HTB{b0f_t0_r00t_v1a_dcmtk}" | sudo tee /root/flag.txt
sudo chmod 600 /root/flag.txt

# Configure vulnerable service to expose flag on crash
echo '[global]
  NetworkTCPPort = 11112
  AEtitle = CTF_SERVER
  MaxPDULength = 16384
  # Insecure crash handler
  OnCrash = /usr/bin/expose_flag.sh' | sudo tee /etc/dcmtk/dcmqrscp.cfg

# Create vulnerable SUID binary
echo '#!/bin/bash
if [ -f "/tmp/exploit_trigger" ]; then
  cat /root/flag.txt
else
  echo "Processing DICOM..."
fi' | sudo tee /usr/bin/vuln_dicom_handler

sudo chmod +s /usr/bin/vuln_dicom_handler

# Create trigger and expose flag
echo '#!/bin/bash
touch /tmp/exploit_trigger
chmod 666 /tmp/exploit_trigger
/usr/bin/vuln_dicom_handler | tee /var/log/flag_exposed.log' | sudo tee /usr/bin/expose_flag.sh

sudo chmod +x /usr/bin/expose_flag.sh