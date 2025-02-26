.PHONY: all build-orthanc build-dmctk build run stop clean deploy-kctf deploy-ansible test

# Variables
ORTHANC_IMAGE = dicom-ctf/orthanc:latest
DMCTK_IMAGE = dicom-ctf/dmctk:latest
KCTF_PROJECT = kctf-demo
KCTF_CLUSTER = kctf-cluster
KCTF_IMAGE = gcr.io/$(KCTF_PROJECT)/dicom-ctf:1.0.0

all: build

# Build Docker images
build: build-orthanc build-dmctk

build-orthanc:
	@echo "Building Orthanc server image..."
	docker build -t $(ORTHANC_IMAGE) challenge/orthanc/

build-dmctk:
	@echo "Building DMCTK server image..."
	docker build -t $(DMCTK_IMAGE) challenge/dmctk/

# Run the challenge locally
run:
	@echo "Starting DICOM CTF environment..."
	docker-compose -f kctf/docker-compose.yml up -d

stop:
	@echo "Stopping DICOM CTF environment..."
	docker-compose -f kctf/docker-compose.yml down

# Clean up resources
clean: stop
	@echo "Cleaning up resources..."
	docker rmi $(ORTHANC_IMAGE) $(DMCTK_IMAGE) || true
	rm -rf *.log

# Deploy to kCTF
deploy-kctf:
	@echo "Deploying to kCTF..."
	kctf chal create dicom-ctf --template kctf/challenge.yaml
	kctf chal start

# Deploy using Ansible
deploy-ansible:
	@echo "Deploying with Ansible..."
	cd ansible && ansible-playbook -i inventory playbook.yml

# Test challenge
test:
	@echo "Testing DICOM CTF challenge..."
	python3 tests/test_connectivity.py

# Generate challenge documentation
docs:
	@echo "Generating challenge documentation..."
	mkdir -p docs
	cd docs && pandoc ../README.md -o dicom-ctf.pdf
	@echo "Documentation generated: docs/dicom-ctf.pdf"

# Setup development environment
setup-dev:
	@echo "Setting up development environment..."
	pip install -r requirements-dev.txt
	pre-commit install

# Setup kCTF environment
setup-kctf:
	@echo "Setting up kCTF environment..."
	kctf cluster create --project=$(KCTF_PROJECT) --cluster-name=$(KCTF_CLUSTER)
	kctf cluster start

help:
	@echo "DICOM CTF Makefile targets:"
	@echo "  build          - Build Docker images for Orthanc and DMCTK servers"
	@echo "  run            - Run the challenge locally using docker-compose"
	@echo "  stop           - Stop the local challenge environment"
	@echo "  clean          - Clean up resources"
	@echo "  deploy-kctf    - Deploy challenge to kCTF"
	@echo "  deploy-ansible - Deploy using Ansible playbooks"
	@echo "  test           - Run tests against the challenge"
	@echo "  docs           - Generate challenge documentation"
	@echo "  setup-dev      - Setup development environment"
	@echo "  setup-kctf     - Setup kCTF environment"