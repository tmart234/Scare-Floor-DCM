#!/usr/bin/env python3
import requests
import socket
import sys
import time

def test_orthanc_web():
    """Test connectivity to Orthanc web interface"""
    try:
        response = requests.get("http://localhost:8042/system", timeout=5)
        if response.status_code == 200:
            print("✅ Orthanc web interface is accessible")
            return True
        else:
            print(f"❌ Orthanc web interface returned status code {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to connect to Orthanc web interface: {e}")
        return False

def test_orthanc_dicom():
    """Test connectivity to Orthanc DICOM port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('localhost', 4242))
        sock.close()
        
        if result == 0:
            print("✅ Orthanc DICOM port is accessible")
            return True
        else:
            print("❌ Orthanc DICOM port is not accessible")
            return False
    except Exception as e:
        print(f"❌ Failed to connect to Orthanc DICOM port: {e}")
        return False

def test_dmctk_web():
    """Test connectivity to DMCTK web interface"""
    try:
        response = requests.get("http://localhost:5000/", timeout=5)
        if response.status_code == 200:
            print("✅ DMCTK web interface is accessible")
            return True
        else:
            print(f"❌ DMCTK web interface returned status code {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to connect to DMCTK web interface: {e}")
        return False

def test_proxy():
    """Test connectivity to the main CTF entry point"""
    try:
        response = requests.get("http://localhost:1337/", timeout=5)
        if response.status_code == 200:
            print("✅ Main CTF entry point is accessible")
            return True
        else:
            print(f"❌ Main CTF entry point returned status code {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to connect to main CTF entry point: {e}")
        return False

def main():
    print("Testing DICOM CTF connectivity...")
    print("================================")
    
    # Wait a bit for services to start
    time.sleep(5)
    
    tests = [
        test_orthanc_web,
        test_orthanc_dicom,
        test_dmctk_web,
        test_proxy
    ]
    
    results = [test() for test in tests]
    
    if all(results):
        print("\n✅ All connectivity tests passed!")
        return 0
    else:
        print("\n❌ Some connectivity tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())