Scare Floor DCM is a vulnerable DICOM CTF

## Build & Run CTF VM

1. **Install Prerequisites**:
   - Install [Packer](https://developer.hashicorp.com/packer/docs/install) for VM creation
   - Install [Vagrant](https://developer.hashicorp.com/vagrant/docs/installation) for running multiple VMs on an isolated network
   - Install [VirtualBox](https://www.virtualbox.org/)
   - Install [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) for automatic machine provisioning and configuration

2. **Build the VMs and Start vagrant**:
   ```bash
   make all

3. **Access DICOM Server**
    - Port: 11112 on host machine
    - Test with:
    ```bash
    dcmsend 127.0.0.1 11112 +sd +aet TESTER sample.dcm

4. **Start VM DICOM tests (optional)**:
   ```bash
   make tests

5. **Cleanup**
    ```bash
    make clean
