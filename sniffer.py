#source port aumenta di 1 dopo ogni messaggio da gui

import socket
import time
import re
from scapy.all import *
import threading
import message_generator
from reply import *

payload_bytes = b""

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.168.0.105", 4088))
sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind(("192.168.0.105", 3000))


def state_machine():
    global payload_bytes

    while True:
        while b"DLA_DISCOVERY;v1.0;FIND_REQ;AnswerPort=" not in payload_bytes:
            pass
        payload_bytes_temp = payload_bytes
        print("Connection request received!")
        match = re.search(r'AnswerPort=(\d+)', payload_bytes.decode('utf-8'))
        answer_port = int(match.group(1))
        print("Answer Port:", answer_port)
        sock.sendto(sls_connection_reply.encode('utf-8'), ('192.168.0.105', answer_port))
        print("response sent!")
        answer_port += 1
        payload_bytes = b""

        while payload_bytes == b"" or payload_bytes == sls_connection_reply.encode('utf-8'):
            pass
        payload_bytes_temp = payload_bytes
        seqnum = int.from_bytes(payload_bytes[4:8], byteorder='big') >> 24
        print("Password request received!")
        reply = message_generator.getPwAndAcReply(seqnum, 0, "admin\0", 1).pack()
        sock1.sendto(reply, ('192.168.0.105', answer_port))
        print("Password response sent!")
        answer_port += 1
        payload_bytes = b""

        while payload_bytes == b"" or payload_bytes == reply:
            pass
        payload_bytes_temp = payload_bytes
        seqnum = int.from_bytes(payload_bytes[4:8], byteorder='big') >> 24
        print("GetStatus request received!")
        reply = message_generator.getStatusReply(seqnum, 0, 0, 0).pack()
        sock1.sendto(reply, ('192.168.0.105', answer_port))
        print("Getstatus response sent!")
        answer_port += 1
        payload_bytes = b""

        '''
        while payload_bytes == b"" or payload_bytes == reply:
            print(f"Waiting for password request: {payload_bytes}")
            pass
        payload_bytes_temp = payload_bytes
        seqnum = int.from_bytes(payload_bytes[4:8], byteorder='big') >> 24
        print(f"Payload bytes: {payload_bytes_temp}")
        '''

        '''
        answer_port += 1
        # salto momentaneamente messaggio di get faults quindi

        time.sleep(1000/1000)
        seqnum = int.from_bytes(payload_bytes[4:8], byteorder='big') >> 24
        reply = message_generator.getHWVerReply(seqnum, 0, sls_get_hw_reply).pack()
        sock1.sendto(reply, ('192.168.0.105', answer_port))
        '''



def packet_handler(pkt):
    global payload_bytes

    if IP in pkt and UDP in pkt:
        if "192.168.0.105" not in pkt[IP].src:
            return
        print(pkt.summary())
        payload_bytes = bytes(pkt[UDP].payload)
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
