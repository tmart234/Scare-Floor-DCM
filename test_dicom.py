from scapy_DICOM import DICOMSession, SCUSCPRoleSelectionSubItem

def test_association_negotiation():
    session = DICOMSession("TEST_CLIENT", "TEST_AE", "localhost")
    assert session.associate(), "Association Failed"
    session.abort()

def test_invalid_ae_title():
    session = DICOMSession("INVALID_AE", "BAD_AE", "localhost")
    assert not session.associate(), "Should reject invalid AE titles"

def test_unsupported_abstract_syntax():
    # Test abstract-syntax-not-supported (PS3.8 9.3.3)
    role_item = SCUSCPRoleSelectionSubItem(
        sop_class_uid="1.2.840.10008.5.1.4.1.1.999",  # Invalid UID
        scu_role=1,
        scp_role=1
    )
    # Should receive A-ASSOCIATE-RJ with result=3
