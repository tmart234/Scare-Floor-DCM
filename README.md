# DICOM-based CTF Challenge

A Capture The Flag (CTF) challenge focused on DICOM medical imaging systems security. The challenge consists of an Orthanc PACS server and a DMCTK server in an isolated network environment.

## Overview

This CTF tests participants' understanding of DICOM protocols, medical imaging systems, and security vulnerabilities in healthcare IT infrastructure. It's designed for medium-skill-level participants who have some familiarity with networking, DICOM concepts, and basic exploitation techniques.

## Prerequisites

- Docker and Docker Compose
- Python 3.6+
- Ansible 2.9+ (for automated deployment)
- kCTF tools (for Kubernetes deployment)

## Directory Structure

```
dicom-ctf/
├── Makefile                 # Build and deployment automation
├── ansible/                 # Ansible playbooks for deployment
├── challenge/               # Challenge source code
│   ├── orthanc/             # Orthanc PACS server
│   └── dmctk/               # DMCTK server
├── kctf/                    # kCTF configuration files
└── README.md                # This file
```

## Quick Start

1. Clone this repository:
   ```
   git clone https://github.com/example/dicom-ctf.git
   cd dicom-ctf
   ```

2. Build the Docker images:
   ```
   make build
   ```

3. Run the challenge locally:
   ```
   make run
   ```

4. Access the challenge at:
   - Main entry point: http://localhost:1337
   - Orthanc Web Interface: http://localhost:8042
   - DMCTK Web Interface: http://localhost:5000

5. Stop the challenge:
   ```
   make stop
   ```

## Deployment Options

### Local Deployment

Use Docker Compose for local testing:
```
make run
```

### kCTF Deployment

Deploy to Kubernetes using kCTF:
```
make setup-kctf    # Only needed once
make deploy-kctf
```

## Challenge Description

"MedImage Crisis"

A major hospital's PACS system has been behaving strangely. Security teams detected unusual patterns in how the DICOM servers are communicating. Your task is to investigate the Orthanc PACS server and its connected DMCTK service to determine if there's a security breach.

The flags are hidden within the system. Find all three to complete the challenge.

## Flags

There are three flags to find:
1. Hidden in a private DICOM tag
2. Embedded in JavaScript source code
3. Only accessible by exploiting a race condition between servers

## Hints

- DICOM protocols often use ports 104 or 11112, but sometimes custom ports are used.
- The DMCTK server's web interface processes search queries in an interesting way.
- DICOM files can contain private tags that aren't part of the standard.

## Resources

The `docs` directory contains additional resources for participants less familiar with DICOM protocols.

## License

This project is licensed under the MIT License - see the LICENSE file for details.