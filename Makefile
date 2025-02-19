.PHONY: all packer-init packer-build vagrant-up test ansible clean

ANSIBLE_PLAYBOOKS = $(wildcard ansible/playbook*.yml)

all: packer-init packer-build ansible vagrant-up

packer-init:
	packer init .

packer-build:
	packer validate scp.pkr.hcl
	packer build scp.pkr.hcl
	packer validate pacs.pkr.hcl
	packer build pacs.pkr.hcl

vagrant-up:
	vagrant up --provision

test:
	python -m pytest test_dicom.py -v

clean:
	rmdir /s /q output-dcmtk-ctf
	rmdir /s /q packer_cache
	rmdir /s /q .vagrant

ansible: $(ANSIBLE_PLAYBOOKS)

$(ANSIBLE_PLAYBOOKS):
	ansible-playbook -i inventory $
	
# use cloud-init to apply specific instance configuration at spawn
