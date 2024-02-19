import ctypes

PWDLENGTH = 8

# Definizione della struttura slsRequest
class slsRequest(ctypes.Structure):
    _fields_ = [
        ("crc", ctypes.c_uint32),          # Cyclic Redundancy Check
        ("seqnum", ctypes.c_uint32),       # Progressive sequence number
        ("password", ctypes.c_char * PWDLENGTH),  # Password
        ("opCode", ctypes.c_uint32)        # Operation Code
    ]

# Definizione della struttura slsReply
class slsReply(ctypes.Structure):
    _fields_ = [
        ("crc", ctypes.c_uint32),          # Cyclic Redundancy Check
        ("seqnum", ctypes.c_uint32),       # Progressive sequence number
        ("opCode", ctypes.c_uint32),       # Operation Code
        ("resCode", ctypes.c_uint32)       # Result Code
    ]

# Definizione della struttura sls_gui_reply_header
class sls_gui_reply_header(ctypes.Structure):
    _fields_ = [
        ("crc", ctypes.c_uint32),          # Cyclic Redundancy Check
        ("seqnum", ctypes.c_uint32),       # Progressive sequence number
        ("opCode", ctypes.c_uint32),       # Operation Code
        ("resCode", ctypes.c_uint32),      # Result Code
        ("version", ctypes.c_uint32),      # Protocol Version
        ("len", ctypes.c_uint32)           # Payload Length
    ]

# Definizione della struttura getPwAndAcRequest
class getPwAndAcRequest(ctypes.Structure):
    _fields_ = [
        ("header", slsRequest)             # Request common field
    ]

# Definizione della struttura getPwAndAcReply
class getPwAndAcReply(ctypes.Structure):
    _fields_ = [
        ("header", slsReply),              # Reply common field
        ("password", ctypes.c_char * PWDLENGTH),  # Password
        ("accessCtrl", ctypes.c_uint32)    # Access Control Level
    ]

# Definizione della struttura setPwAndAcRequest
class setPwAndAcRequest(ctypes.Structure):
    _fields_ = [
        ("header", slsRequest),            # Request common field
        ("newPW", ctypes.c_char * PWDLENGTH),  # New Password
        ("accessCtrl", ctypes.c_uint32),   # Access Control Level
        ("resetPassword", ctypes.c_char * PWDLENGTH)  # Reset Password
    ]

# Definizione della struttura setPwAndAcReply
class setPwAndAcReply(ctypes.Structure):
    _fields_ = [
        ("header", slsReply)               # Reply common field
    ]

# Definizione della struttura startPwResetRequest
class startPwResetRequest(ctypes.Structure):
    _fields_ = [
        ("header", slsRequest)             # Request common field
    ]

# Definizione della struttura startPwResetReply
class startPwResetReply(ctypes.Structure):
    _fields_ = [
        ("header", slsReply),              # Reply common field
        ("sN", ctypes.c_char * 9),         # Serial Number
        ("magic", ctypes.c_uint8)          # Magic Number
    ]

# Definizione della struttura getStatusRequest
class getStatusRequest(ctypes.Structure):
    _fields_ = [
        ("header", slsRequest)             # Request common field
    ]

# Definizione della struttura getStatusReply
class getStatusReply(ctypes.Structure):
    _fields_ = [
        ("header", slsReply),              # Reply common field
        ("status", ctypes.c_uint32),       # Status
        ("transaction", ctypes.c_uint32)   # Transaction
    ]
