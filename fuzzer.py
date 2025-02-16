# Add new file: dicom_fuzzer.py
from boofuzz import *
from scapy_DICOM import DICOM

def build_fuzzer():
    session = Session(
        target=Target(
            connection=SocketConnection("localhost", 104, proto='tcp')
        )
    )

    s_initialize("DICOM_Associate")
    with s_block("DICOM_Header"):
        s_byte(0x01, name="pdu_type", fuzzable=False)  # A-ASSOCIATE-RQ
        s_byte(0x00, name="reserved1", fuzzable=True)
        s_size("length", length=4, endian=">", fuzzable=False)
        
    with s_block("A_ASSOCIATE_RQ"):
        s_word(0x0001, name="protocol_version", fuzzable=True)
        s_random(b"\x00\x00", 2, 2, name="reserved2")
        s_string("TEST_AE", size=16, padding=b'\x00', name="called_ae_title")
        s_string("FUZZ_AE", size=16, padding=b'\x00', name="calling_ae_title")
        s_random(b"\x00"*32, 32, 32, name="reserved3")
        
    session.connect(s_get("DICOM_Associate"))
    session.fuzz()
