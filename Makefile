.PHONY: all packer-init packer-build vagrant-up test clean

all: packer-init packer-build vagrant-up

packer-init:
	packer init .

packer-build:
	packer validate dcmtk-ctf.pkr.hcl
	packer build dcmtk-ctf.pkr.hcl

vagrant-up:
	vagrant up --provision

test:
	python -m pytest test_dicom.py -v

clean:
	rmdir /s /q output-dcmtk-ctf
	rmdir /s /q packer_cache
	rmdir /s /q .vagrant