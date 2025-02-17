Scare Floor DCM is a vulnerable DICOM CTF Box

## Build & Run CTF VM

1. **Install Prerequisites**:
   - Install [Packer](https://developer.hashicorp.com/packer/docs/install) 
   - Install [Vagrant](https://developer.hashicorp.com/vagrant/docs/installation)
   - Install [VirtualBox](https://www.virtualbox.org/)

2. **Build the VM and Start the VM**:
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
