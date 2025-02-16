from boofuzz import *

def build_fuzzer():
    session = Session(target=Target(
        connection=SocketConnection("localhost", 104, proto='tcp')
    ))

    s_initialize("DICOM Associate")
    s_static(b"\x01")  # PDU-Type: A-ASSOCIATE-RQ (0x01)
    s_static(b"\x00")  # Reserved
    s_size("length", length=4, endian=">", fuzzable=False)
    s_group("version_items", values=[b"\x00\x01", b"\xff\xff"])  # Protocol version
    s_random(b"\x00\x00", 2, 2)  # Reserved
    s_string("TEST_CLIENT".ljust(16), size=16)  # Called AE Title
    s_string("TEST_AE".ljust(16), size=16)     # Calling AE Title
    s_random(b"\x00"*32, 32, 32)               # Reserved
  
    session.connect(s_get("DICOM Associate"))
    session.fuzz()
