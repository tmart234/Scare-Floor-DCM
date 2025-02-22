from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet, bind_layers
from scapy.supersocket import StreamSocket
import socket
from scapy.layers.inet import TCP
import struct

# ------------------- DICOM Base Protocol Support -------------------
class DICOM(Packet):
    name = "DICOM"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, {
            0x01: "A-ASSOCIATE-RQ",
            0x02: "A-ASSOCIATE-AC",
            0x03: "A-ASSOCIATE-RJ",
            0x04: "P-DATA-TF",
            0x05: "A-RELEASE-RQ",
            0x06: "A-RELEASE-RP",
            0x07: "A-ABORT"
        }),
        ByteField("reserved1", 0),
        IntField("length", None),
    ]
    
    def post_build(self, p, pay):
        if self.length is None:
            length = len(pay)
            p = p[:2] + struct.pack("!I", length) + p[6:]
        return p + pay

# ------------------- Association Control PDUs -------------------
class DICOMVariableItem(Packet):
    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, {
            0x10: "Application Context",
            0x20: "Presentation Context",
            0x21: "Presentation Context ACK",
            0x50: "User Information"
        }),
        ByteField("reserved", 0),
        ShortField("length", None),
        StrLenField("data", b"", length_from=lambda x: x.length),
    ]
    
    def post_build(self, p, pay):
        if self.length is None:
            length = len(self.data)
            p = p[:2] + struct.pack("!H", length) + p[4:]
        return p + pay
    
class DICOMField(Packet):
    fields_desc = [
        ShortField("group", None),
        ShortField("element", None),
        StrFixedLenField("VR", None, 2),
        ShortField("reserved", 0),
        FieldLenField("length", None, fmt="I"),
        StrLenField("value", "", length_from=lambda x: x.length)
    ]

    def __init__(self, group, element, VR, value, **kwargs):
        super().__init__(group=group, element=element, VR=VR, 
                        length=len(value), value=value, **kwargs)
        
class DICOMDataset(Packet):
    fields_desc = [PacketListField("fields", [], DICOMField)]
    
    def __bytes__(self):
        return b"".join(bytes(field) for field in self.fields)

class UserInformationItem(Packet):
    name = "User Information Sub-item"
    fields_desc = [
        ByteEnumField("item_type", 0x51, {
            0x51: "Maximum Length",
            0x52: "Implementation Class UID",
            0x53: "Asynchronous Operations Window",
            0x54: "SCP/SCU Role Selection",
            0x55: "Implementation Version"
        }),
        ByteField("reserved", 0),
        ShortField("length", None),
        StrLenField("data", b"", length_from=lambda x: x.length),
    ]
    
    def post_build(self, p, pay):
        if self.length is None:
            length = len(self.data)
            p = p[:2] + struct.pack("!H", length) + p[4:]
        return p + pay

class AsyncOperationsWindowSubItem(Packet):
    name = "Asynchronous Operations Window Sub-item"
    fields_desc = [
        ByteField("item_type", 0x53),
        ByteField("reserved", 0),
        ShortField("item_length", 4),
        ShortField("max_operations_invoked", 1),
        ShortField("max_operations_performed", 1),
    ]
    
    def post_build(self, p, pay):
        if self.item_length is None:
            p = p[:2] + struct.pack("!H", 4) + p[4:]
        return p + pay

class SCUSCPRoleSelectionSubItem(Packet):
    name = "SCU/SCP Role Selection Sub-item"
    fields_desc = [
        ByteField("item_type", 0x54),
        ByteField("reserved", 0),
        ShortField("item_length", None),
        ShortField("uid_length", None),
        StrLenField("sop_class_uid", "", length_from=lambda x: x.uid_length),
        ByteField("scu_role", 0),
        ByteField("scp_role", 0),
    ]
    
    def post_build(self, p, pay):
        if self.uid_length is None:
            uid_len = len(self.sop_class_uid)
            p = p[:4] + struct.pack("!H", uid_len) + p[6:]
        if self.item_length is None:
            uid_len = struct.unpack("!H", p[4:6])[0]
            item_len = uid_len + 4
            p = p[:2] + struct.pack("!H", item_len) + p[4:]
        return p + pay

class A_ASSOCIATE_RQ(Packet):
    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 0x0001),
        ShortField("reserved2", 0),
        StrFixedLenField("called_ae_title", b"", 16),
        StrFixedLenField("calling_ae_title", b"", 16),
        StrFixedLenField("reserved3", b"\x00"*32, 32),
        PacketListField("variable_items", [], DICOMVariableItem),
    ]
    pres_context = DICOMVariableItem(
    item_type=0x20,
    data=bytes([
        0x30, 0x00,  # Presentation Context ID
        0x00, 0x00, 0x00, 0x40,  # Item length
        0x01, 0x00, 0x00, 0x00,  # Abstract syntax: 1.2.840.10008.5.1.4.1.1.2 (CT Storage)
        0x30, 0x00, 0x00, 0x00,  # Transfer syntax: 1.2.840.10008.1.2 (Implicit VR Little Endian)
    ])
)

class A_ASSOCIATE_AC(A_ASSOCIATE_RQ):
    name = "A-ASSOCIATE-AC"

class A_ASSOCIATE_RJ(Packet):
    name = "A-ASSOCIATE-RJ"
    fields_desc = [
        ByteField("reserved1", 0),
        ByteEnumField("result", 1, {1: "Rejected (permanent)", 2: "Rejected (transient)"}),
        ByteEnumField("source", 1, {1: "DICOM UL service-user", 2: "Service provider (ACSE)", 3: "Reserved"}),
        ByteEnumField("reason", 1, {1: "No reason given", 2: "Protocol version not supported"}),
    ]

class A_RELEASE_RQ(Packet):
    name = "A-RELEASE-RQ"  
    fields_desc = [
        IntField("reserved", 0), 
        IntField("reason", 0x00000000)
    ]

class A_RELEASE_RP(A_RELEASE_RQ):
    name = "A-RELEASE-RP"

class A_ABORT(Packet):
    name = "A-ABORT"
    fields_desc = [
        ByteEnumField("source", 0, {0: "DICOM UL service-user", 2: "UL service-provider"}),
        ByteField("reason", 0x00),
        ShortField("reserved", 0),
    ]

class P_DATA_TF(Packet):
    name = "P-DATA-TF"
    fields_desc = [
        IntField("pdv_length", None),
        ByteField("context_id", 0),
        ByteField("flags", 0),
        ShortField("command_set", 0),
        StrLenField("data", b"", length_from=lambda x: x.pdv_length-4)
    ]
    
    def post_build(self, p, pay):
        if self.pdv_length is None:  # Restore conditional check
            pdv_length = len(self.data) + 4
            p = struct.pack("!I", pdv_length) + p[4:]
        return p + pay

# ------------------- Layer Binding -------------------
bind_layers(TCP, DICOM, sport=11112)
bind_layers(TCP, DICOM, dport=11112)
bind_layers(TCP, DICOM, sport=105)
bind_layers(TCP, DICOM, dport=105)

bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)

bind_layers(UserInformationItem, AsyncOperationsWindowSubItem, item_type=0x53)
bind_layers(UserInformationItem, SCUSCPRoleSelectionSubItem, item_type=0x54)

# ------------------- Network Manager -------------------
class DICOMSession:
    def __init__(self, src_ae, dst_ae, dst_ip, dst_port=11112):  # Match server port
        # AE title validation
        if len(src_ae) > 16 or len(dst_ae) > 16:
            raise ValueError("AE titles must be ≤16 characters (DICOM PS3.7 D.3.3.3)")
            
        self.src_ae = src_ae.ljust(16)
        self.dst_ae = dst_ae.ljust(16)
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._connect_with_retry()
        self.stream = StreamSocket(self.s, DICOM)  # Initialize here
        self.assoc_established = False
        self.context_id = 1

    def _connect_with_retry(self, retries=5, delay=3):
        for attempt in range(retries):
            try:
                self.s.settimeout(5)
                self.s.connect((self.dst_ip, self.dst_port))
                return
            except socket.error as e:
                if attempt == retries - 1:
                    raise ConnectionError(f"Connection failed after {retries} attempts: {e}")
                time.sleep(delay)

    def associate(self):
        app_context = DICOMVariableItem(
            item_type=0x10,
            data=b"1.2.840.10008.3.1.1.1"  # DICOM App Context
        )
        
        user_info = DICOMVariableItem(item_type=0x50)
        max_pdu = UserInformationItem(
            item_type=0x51,
            data=struct.pack("!I", 16384)  # Max PDU size
        )
        async_window = AsyncOperationsWindowSubItem(
            max_operations_invoked=10,
            max_operations_performed=5
        )
        role_selection = SCUSCPRoleSelectionSubItem(
            sop_class_uid="1.2.840.10008.5.1.4.1.1.2",  # CT Image Storage
            scu_role=1,
            scp_role=1
        )
        user_info_data = bytes(max_pdu) + bytes(async_window) + bytes(role_selection)
        user_info.data = user_info_data
        
        assoc_rq = A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae.encode(),
            calling_ae_title=self.src_ae.encode(),
            variable_items=[app_context, user_info]
        )
        
        dicom_pkt = DICOM(pdu_type=0x01)/assoc_rq
        self.stream.send(dicom_pkt)
        try:
            response = self.stream.recv()
            if response and response.haslayer(A_ASSOCIATE_AC):
                self.assoc_established = True
                return True
            return False
        except Exception as e:
            print(f"Association failed: {e}")
            return False

    def send_data(self, dataset):
        if not self.assoc_established:
            raise Exception("No active association")
        pdv = P_DATA_TF(context_id=self.context_id, data=dataset)
        dicom_pkt = DICOM(pdu_type=0x04)/pdv
        self.stream.send(dicom_pkt)

    def release(self):
        release_rq = A_RELEASE_RQ()
        dicom_pkt = DICOM(pdu_type=0x05)/release_rq
        self.stream.send(dicom_pkt)
        try:
            response = self.stream.recv()
            if response and response.haslayer(A_RELEASE_RP):
                self.assoc_established = False
                self.s.close()
                return True
            self.s.close()
            return False
        except Exception as e:
            print(f"Release failed: {e}")
            self.s.close()
            return False

    def abort(self):
        abort_pkt = A_ABORT(source=0, reason=0)
        dicom_pkt = DICOM(pdu_type=0x07)/abort_pkt
        try:
            self.stream.send(dicom_pkt)
        except:
            pass
        self.assoc_established = False
        self.s.close()
