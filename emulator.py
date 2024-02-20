from scapy.all import *
import threading
import message_generator
from reply import *

GUI_IP = "192.168.0.105"
payload_bytes = b""
source_port = 0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((GUI_IP, 4088))
sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock1.bind((GUI_IP, 3000))


def right_shift_to_the_first_one(decimal_number):
    binary_number = bin(decimal_number)[2:]
    count = 0

    for bit in reversed(binary_number):
        if bit == '0':
            count += 1
        else:
            break
    shifted_binary_number = '0' * count + binary_number[:-count]
    try:
        shifted_decimal_number = int(shifted_binary_number, 2)
    except ValueError:
        shifted_decimal_number = 0
    return shifted_decimal_number


def get_info_task():
    global payload_bytes

    while b"DLA_DISCOVERY;v1.0;FIND_REQ;" not in payload_bytes:
        source_port_temp, payload_bytes_temp = wait_for_message(b"DLA_DISCOVERY;v1.0;DIAG_REQ;MAC=")
        sock.sendto(sls_info_reply.encode('utf-8'), (GUI_IP, source_port_temp))
        print(f"reply: {sls_info_reply}")


def send_discovery(device_family, device_model, device_protocol):
    GUI_PORT = 1073

    for i in range(3):
        discovery_res = f"DLA_DISCOVERY;v1.0;FIN;DeviceName=;DeviceFamily={device_family};IsSimulator=False;" \
                        f"DeviceModelName={device_model};DeviceSerial=C19P00708;MAC=00:07:be:08:8f:e1;" \
                        f"ProtocolType={device_protocol};" \
                        f"SwVersion=03.02.00.66;MibSchemaVersion=8.0.0;Status=Running=on-line;" \
                        f"SubnetMask=255.255.255.0;GatewayAddress=192.168.0.1;Dns1Address=8.8.8.8;" \
                        f"Dns2Address=8.8.4.4;UseDhcp=False;SlavesNumber=0;"
        sock.sendto(discovery_res.encode('utf-8'), (GUI_IP, GUI_PORT))
        print(f"> {discovery_res}")
        time.sleep(1 / 2)


def wait_for_message(byte_message=b"", previous_reply=b"impossible", previous_answer=b"impossible"):
    global payload_bytes
    global source_port

    payload_bytes = b""
    source_port = 0
    while byte_message not in payload_bytes or payload_bytes == b"" or payload_bytes == previous_reply or payload_bytes == previous_answer:
        pass
    payload_bytes_temp = payload_bytes
    source_port_temp = source_port
    print(f"message accepted: {payload_bytes}\n")

    return source_port_temp, payload_bytes_temp


def state_machine():
    global payload_bytes
    global source_port

    while True:
        # discovery messages
        wait_for_message(b"DLA_DISCOVERY;v1.0;FIND_REQ;")
        send_discovery("SLS-M5-0812-E", "958001110", "SLS")

        # discovery + answerport messages
        source_port_temp, payload_bytes_temp = wait_for_message(b"DLA_DISCOVERY;v1.0;FIND_REQ;AnswerPort=")
        sock.sendto(sls_connection_reply.encode('utf-8'), (GUI_IP, source_port_temp))

        # password request messages
        print("--- waiting for password request ---")
        source_port_temp, payload_bytes_temp = wait_for_message(previous_reply=sls_connection_reply.encode('utf-8'))
        print(" --- password request received ---")
        seqnum = int.from_bytes(payload_bytes_temp[4:8], byteorder='little')
        print(f"seqnum: {seqnum}")
        reply = message_generator.getPwAndAcReply(seqnum, 0, "admin\0", 1).pack()
        sock1.sendto(reply, (GUI_IP, source_port_temp))
        print(f"reply: {reply}")

        # getstatus request messages
        print("--- waiting for getstatus request ---")
        source_port_temp, payload_bytes_temp = wait_for_message("\x03\x00\x00\x00".encode('utf-8'))
        print(" --- getstatus request received ---")
        seqnum = int.from_bytes(payload_bytes_temp[4:8], byteorder='little')
        print(f"seqnum: {seqnum}")
        reply = message_generator.getStatusReply(seqnum, 0, 0, 0).pack()
        sock1.sendto(reply, (GUI_IP, source_port_temp))
        print(f"reply: {reply}")

        # get device info cyclic messages
        threading.Thread(target=get_info_task).start()

        # get-hw-versions messages
        print("--- waiting for get-hw-versions request ---")
        source_port_temp, payload_bytes_temp = wait_for_message("\x2c\x00\x00\x00".encode('utf-8'))
        print(" --- get-hw-versions request received ---")
        seqnum = int.from_bytes(payload_bytes_temp[4:8], byteorder='little')
        print(f"seqnum: {seqnum}")
        reply = message_generator.getHWVerReply(seqnum, 0, sls_get_hw_reply).pack()
        sock1.sendto(reply, (GUI_IP, source_port_temp))
        print(f"reply: {reply}")

        # getstatus request messages
        print("--- waiting for getstatus request ---")
        source_port_temp, payload_bytes_temp = wait_for_message("\x03\x00\x00\x00".encode('utf-8'))
        print(" --- getstatus request received ---")
        seqnum = int.from_bytes(payload_bytes_temp[4:8], byteorder='little')
        print(f"seqnum: {seqnum}")
        reply = message_generator.getStatusReply(seqnum, 0, 0, 0).pack()
        sock1.sendto(reply, (GUI_IP, source_port_temp))
        print(f"reply getstatus sent: {reply}")


def packet_handler(pkt):
    global payload_bytes
    global source_port

    if IP in pkt and UDP in pkt:
        if GUI_IP not in pkt[IP].src:
            return
        payload_bytes = bytes(pkt[UDP].payload)
        source_port = pkt[UDP].sport
        #print(f"{payload_bytes}\n")


def start_sniffer(interface):
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_handler, filter="udp")


def print_interfaces_list():
    print(ifaces)


if __name__ == "__main__":
    # print_interfaces_list()
    interface = "Software Loopback Interface 1"
    threading.Thread(target=state_machine).start()
    start_sniffer(interface)
