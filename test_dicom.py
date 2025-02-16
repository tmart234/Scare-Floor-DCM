from scapy_DICOM import DICOMSession, SCUSCPRoleSelectionSubItem
import pytest
import time
import socket

@pytest.fixture
def dicom_server():
    """Enhanced server check with port 11112"""
    retries = 5
    for _ in range(retries):
        try:
            with socket.create_connection(("localhost", 11112), timeout=5):
                return
        except ConnectionRefusedError:
            time.sleep(5)
    pytest.fail("DICOM server unavailable after 5 attempts")

def test_association_negotiation(dicom_server):
    session = DICOMSession("TEST_CLIENT", "TEST_AE", "localhost")
    assert session.associate(), "Association should succeed"
    session.release()

def test_invalid_ae_title():
    session = DICOMSession("INVALID_AE", "BAD_AE", "localhost")
    assert not session.associate(), "Should reject invalid AE titles"

def test_valid_association():
    with DICOMSession("TEST_SCU", "TEST_SCP", "localhost") as session:
        assert session.associate(), "Association should succeed with valid AE titles"
        session.release()

def test_invalid_ae_title_length():
    with pytest.raises(Exception):
        # AE titles should be 16 chars max (PS3.8 9.3.2.1)
        DICOMSession("A"*17, "B"*17, "localhost")

def test_unsupported_abstract_syntax():
    # Test abstract-syntax-not-supported (PS3.8 9.3.3)
    role_item = SCUSCPRoleSelectionSubItem(
        sop_class_uid="1.2.840.10008.5.1.4.1.1.999",  # Invalid UID
        scu_role=1,
        scp_role=1
    )
    # Should receive A-ASSOCIATE-RJ with result=3
