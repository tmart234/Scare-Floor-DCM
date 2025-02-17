.PHONY: all packer-build vagrant-up test clean

all: packer-build vagrant-up

packer-build:
	packer init .
	packer build dcmtk-ctf.pkr.hcl

vagrant-up:
	vagrant up --provision

test:
	python3 -m pytest test_dicom.py -v

clean:
	vagrant destroy -f
	rm -rf output/ dcmtk-ctf.box