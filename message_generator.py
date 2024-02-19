import struct
import socket
import crc

# Definizione delle costanti
PWDLENGTH = 8
NOPASSWORD = 0
WRONLYPASSWORD = 1
RDWRPASSWORD = 3
LAST_ACCESS_LEVEL = RDWRPASSWORD + 1

# ------------------ REPLY/REQUEST FORMAT -----------------------------------------------------------------------------
class slsRequest:
    def __init__(self, crc, seqnum, password, opCode):
        self.crc = crc
        self.seqnum = seqnum
        self.password = password
        self.opCode = opCode

    def pack(self):
        return struct.pack('II8sI', self.crc, self.seqnum, self.password.encode('utf-8'), self.opCode)


class slsReply:
    def __init__(self, crc, seqnum, opCode, resCode):
        self.crc = crc
        self.seqnum = seqnum
        self.opCode = opCode
        self.resCode = resCode

    def pack(self):
        return struct.pack('<IIII', self.crc, self.seqnum, self.opCode, self.resCode)


class sls_gui_reply_header:
    def __init__(self, crc, seqnum, opCode, resCode, version, length):
        self.crc = crc
        self.seqnum = seqnum
        self.opCode = opCode
        self.resCode = resCode
        self.version = version
        self.length = length

    def pack(self):
        return struct.pack('<IIIIII', self.crc, self.seqnum, self.opCode, self.resCode, self.version, self.length)
# ---------------------------------------------------------------------------------------------------------------------


# ------------------ SLS MESSAGES -------------------------------------------------------------------------------------
class getPwAndAcReply:
    def __init__(self, seqnum, resCode, password, accessCtrl):
        opCode = 0
        self.header = slsReply(0, seqnum, opCode, resCode)
        self.password = password
        self.accessCtrl = accessCtrl

        self.crc_updater()

    def pack(self):
        return self.header.pack() + struct.pack('<8sI', self.password.encode('utf-8'), self.accessCtrl)

    def crc_updater(self):
        crc_input = self.pack()[4:]
        crc_value = crc.crc_compute(crc_input, len(crc_input))
        self.header.crc = crc_value


class getStatusReply:
    def __init__(self, seqnum, resCode, status, transaction):
        opCode = 3
        self.header = slsReply(0, seqnum, opCode, resCode)
        self.status = status
        self.transaction = transaction

        self.crc_updater()

    def pack(self):
        return self.header.pack() + struct.pack('II', self.status, self.transaction)

    def crc_updater(self):
        crc_input = self.pack()[4:]
        crc_value = crc.crc_compute(crc_input, len(crc_input))
        self.header.crc = crc_value


class getHWVerReply:
    def __init__(self, seqnum, resCode, sls_hw_description):
        opCode = 44
        self.header = slsReply(0, seqnum, opCode, resCode)
        self.sls_hw_description = sls_hw_description

        self.crc_updater()

    def pack(self):
        return self.header.pack() + struct.pack('1300s', self.sls_hw_description.encode('utf-8'))

    def crc_updater(self):
        crc_input = self.pack()[4:]
        crc_value = crc.crc_compute(crc_input, len(crc_input))
        self.header.crc = crc_value
# ---------------------------------------------------------------------------------------------------------------------


# ------------------ GUI MESSAGES -------------------------------------------------------------------------------------
# da rivedere (crc, opcode ecc...)
class getPwAndAcRequest:
    def __init__(self, crc, seqnum, password):
        opCode = 0
        self.header = slsRequest(crc, seqnum, password, opCode)

    def pack(self):
        return self.header.pack()


class getStatusRequest:
    def __init__(self, crc, seqnum, password):
        opCode = 3
        self.header = slsRequest(crc, seqnum, password, opCode)

    def pack(self):
        return self.header.pack()

# ---------------------------------------------------------------------------------------------------------------------


UDP_IP = "192.168.0.105"
UDP_PORT = 3000


def send_message(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (UDP_IP, UDP_PORT))


if __name__ == "__main__":
    '''
    # Esempio di invio di una richiesta per ottenere la password e il livello di accesso
    get_pw_and_ac_request = getPwAndAcRequest(1234, 1, "admin")
    get_pw_and_ac_request_bytes = get_pw_and_ac_request.pack()
    print("Sending get password and access control request:", get_pw_and_ac_request_bytes)
    send_message(get_pw_and_ac_request_bytes)

    # Esempio di invio di una risposta alla richiesta per ottenere la password e il livello di accesso
    get_pw_and_ac_reply = getPwAndAcReply(1, 0, "admin", 1)
    get_pw_and_ac_reply_bytes = get_pw_and_ac_reply.pack()
    print("Sending get password and access control reply:", get_pw_and_ac_reply_bytes)
    send_message(get_pw_and_ac_reply_bytes)

    # Esempio di invio di una richiesta per ottenere lo stato
    status_request = getStatusRequest(1234, 1, "admin")
    status_request_bytes = status_request.pack()
    print("Sending status request:", status_request_bytes)
    send_message(status_request_bytes)

    # Esempio di invio di una risposta allo stato
    status_reply = getStatusReply(4321, 1, 3, 0, 1)
    status_reply_bytes = status_reply.pack()
    print("Sending status reply:", status_reply_bytes)
    send_message(status_reply_bytes)
    '''
    reply = getStatusReply(10, 0, 0, 0).pack()
    print(reply)
