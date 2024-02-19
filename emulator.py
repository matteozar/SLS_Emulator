#source port aumenta di 1 dopo ogni messaggio da gui

import socket
import time
import re
from scapy.all import *
import threading
import message_generator
from reply import *

payload_bytes = b""
source_port = 0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.168.0.105", 4088))
sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind(("192.168.0.105", 3000))


def send_discovery(device_family, device_model, device_protocol):
    GUI_PORT = 1073

    for i in range(3):
        discovery_res = f"DLA_DISCOVERY;v1.0;FIN;DeviceName=;DeviceFamily={device_family};IsSimulator=False;" \
                        f"DeviceModelName={device_model};DeviceSerial=C19P00708;MAC=00:07:be:08:8f:e1;" \
                        f"ProtocolType={device_protocol};" \
                        f"SwVersion=03.02.00.66;MibSchemaVersion=8.0.0;Status=Running=on-line;" \
                        f"SubnetMask=255.255.255.0;GatewayAddress=192.168.0.1;Dns1Address=8.8.8.8;" \
                        f"Dns2Address=8.8.4.4;UseDhcp=False;SlavesNumber=0;"
        sock.sendto(discovery_res.encode('utf-8'), ("192.168.0.105", GUI_PORT))
        print(f"> {discovery_res}")
        time.sleep(1 / 2)


def state_machine():
    global payload_bytes
    global source_port

    while True:
        while b"DLA_DISCOVERY;v1.0;FIND_REQ;" not in payload_bytes:
            pass
        print("Connection request received!")
        send_discovery("SLS-M5-0812-E", "958001110", "SLS")

        while b"DLA_DISCOVERY;v1.0;FIND_REQ;AnswerPort=" not in payload_bytes:
            pass
        print("Connection request received!")
        payload_bytes_temp = payload_bytes
        source_port_tmp = source_port
        match = re.search(r'AnswerPort=(\d+)', payload_bytes_temp.decode('utf-8'))
        answer_port = int(match.group(1))
        sock.sendto(sls_connection_reply.encode('utf-8'), ('192.168.0.105', source_port_tmp))
        print("Connection response sent!")
        print("Answer Port acquired:", source_port_tmp)

        payload_bytes = b""

        while payload_bytes == b"" or payload_bytes == sls_connection_reply.encode('utf-8'):
            pass
        print("Password request received!")
        payload_bytes_temp = payload_bytes
        source_port_tmp = source_port
        seqnum = int.from_bytes(payload_bytes_temp[4:8], byteorder='big') >> 24
        reply = message_generator.getPwAndAcReply(seqnum, 0, "admin\0", 1).pack()
        sock1.sendto(reply, ('192.168.0.105', source_port_tmp))
        print("Password response sent!")
        print("Answer Port password message:", source_port_tmp)

        payload_bytes = b""

        while payload_bytes == b"" or payload_bytes == reply:
            pass
        print("GetStatus request received!")
        payload_bytes_temp = payload_bytes
        source_port_tmp = source_port
        seqnum = int.from_bytes(payload_bytes_temp[4:8], byteorder='big') >> 24
        reply = message_generator.getStatusReply(seqnum, 0, 0, 0).pack()
        sock1.sendto(reply, ('192.168.0.105', source_port_tmp))
        print("Getstatus response sent!")
        print("Answer Port getstatus message:", source_port_tmp)

        while b"DLA_DISCOVERY;v1.0;DIAG_REQ;MAC=" not in payload_bytes:
            pass
        print("Info request received!")
        source_port_tmp = source_port
        sock.sendto(sls_info_reply.encode('utf-8'), ('192.168.0.105', source_port_tmp))
        print("Info response sent!")
        print("Answer Port info message:", source_port_tmp)

        payload_bytes = b""

        while "\x2c\x00\x00\x00".encode('utf-8') not in payload_bytes:
            pass
        print("HW version request received!")
        payload_bytes_temp = payload_bytes
        source_port_tmp = source_port

        seqnum = int.from_bytes(payload_bytes_temp[4:8], byteorder='big') >> 24
        reply = message_generator.getHWVerReply(seqnum, 0, sls_get_hw_reply).pack()
        sock1.sendto(reply, ('192.168.0.105', source_port_tmp))
        print("HW version response sent!")
        print("Answer Port HW version message:", source_port_tmp)

        payload_bytes = b""

        while True:
            while b"DLA_DISCOVERY;v1.0;DIAG_REQ;MAC=" not in payload_bytes:
                pass
            source_port_tmp = source_port
            print("Info request received!")
            sock.sendto(sls_info_reply.encode('utf-8'), ('192.168.0.105', source_port_tmp))
            print("Info response sent!")
            print("Answer Port info message:", source_port_tmp)

            answer_port += 1
            payload_bytes = b""


def packet_handler(pkt):
    global payload_bytes
    global source_port

    if IP in pkt and UDP in pkt:
        if "192.168.0.105" not in pkt[IP].src:
            return
        print(pkt.summary())
        payload_bytes = bytes(pkt[UDP].payload)
        source_port = pkt[UDP].sport
        print(f"    {payload_bytes}\n")


def start_sniffer(interface):
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_handler, filter="udp")


def print_interfaces_list():
    print(ifaces)


if __name__ == "__main__":
    print_interfaces_list()
    interface = "Software Loopback Interface 1"
    threading.Thread(target=state_machine).start()
    start_sniffer(interface)
