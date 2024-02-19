import tkinter as tk
from tkinter import ttk
import socket
import time
from threading import Thread

# dictionary that contains the data of the devices
data = {
    'SLS-SA3-08': ['958001080', 'SLS'],
    'SLS-SA5-08': ['958001090', 'SLS'],
    'SLS-M3-0812-E': ['958001020', 'SLS'],
    'SLS-M3-1708-E': ['958001010', 'SLS'],
    'SLS-M5-0812-E': ['958001110', 'SLS'],
    'SLS-M5-1708-E': ['958001030', 'SLS'],
    'SLS-M5-E-1708-E': ['958001050', 'SLS'],
    'SLS-R3-E': ['958001060', 'SLS'],
    'SLS-R5-E': ['958001120', 'SLS'],
    'PSEN sc M 5.5 08-17': ['6D000019', 'PSENscan'],
    'PSEN sc ME 5.5 08-17': ['6D000034', 'PSENscan'],
    'PSEN sc M 5.5 08-12': ['6D000017', 'PSENscan'],
    'PSEN sc M 3.0 08-12': ['6D000016', 'PSENscan'],
    'PSEN sc S 5.5 08-12': ['6D000021', 'PSENscan'],
    'PSEN sc S 3.0 08-12': ['6D000020', 'PSENscan'],
    'PSEN sc L 5.5 08-12': ['6D000013', 'PSENscan'],
    'PSEN sc L 3.0 08-12': ['6D000012', 'PSENscan'],
    'SX5-B': ['806006', 'SLS-Banner'],
    'SX5-R': ['807770', 'SLS-Banner'],
    'SX5-M10': ['807769', 'SLS-Banner'],
    'SX5-B6': ['809737', 'SLS-Banner'],
    'SX5-M70': ['807768', 'SLS-Banner'],
    'SX5-ME70': ['807767', 'SLS-Banner'],
    'ASL10-3E': ['958000029', 'SLS-Elco'],
    'ASL10-5E': ['958000030', 'SLS-Elco']
}


# class that creates the GUI
class DiscoverySimulatorGUI:
    def __init__(self, root):
        self.sock = None
        self.root = root
        self.root.title("Discovery Simulator")
        self.root.geometry("280x170")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.device_family_var = tk.StringVar()
        self.device_family_var.set("SLS-M5-0812-E")
        self.running = False

        self.create_widgets()

    # method that creates the widgets
    def create_widgets(self):
        discovery_frame = ttk.Frame(self.root)
        discovery_frame.rowconfigure(3, weight=1)
        discovery_frame.columnconfigure(0, weight=1)
        discovery_frame.grid(row=0, column=0, padx=10, pady=10,  sticky="nswe")

        ip_label = ttk.Label(discovery_frame, text="PC Ethernet IP")
        ip_label.grid(row=0, column=0, padx=10, sticky="")
        self.ip_entry = ttk.Entry(discovery_frame)
        self.ip_entry.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="")
        self.ip_entry.insert(0, "192.168.0.105")

        device_family_menu = ttk.Combobox(discovery_frame, textvariable=self.device_family_var,
                                          values=list(data.keys()), state="readonly")
        device_family_menu.grid(row=2, column=0, padx=10, pady=10, sticky="")

        self.start_stop_button = tk.Button(discovery_frame, text="Start", command=self.toggle_discovery, width=10)
        self.start_stop_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="")

    # method that opens the socket
    def open_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # method that toggles the discovery
    def toggle_discovery(self):
        if self.running:
            self.stop_discovery()
        else:
            self.start_discovery()

    # method that starts the discovery
    def start_discovery(self):
        if not self.running:
            device_family = self.device_family_var.get()
            device_model = data[device_family][0]
            device_protocol = data[device_family][1]

            self.running = True
            self.start_stop_button.config(text="Stop")
            self.thread = Thread(target=self.send_discovery, args=(device_family, device_model, device_protocol))
            self.thread.start()

    # method that stops the discovery
    def stop_discovery(self):
        if self.running:
            self.running = False
            self.start_stop_button.config(text="Start")
            self.thread.join()

    # method that sends the discovery
    def send_discovery(self, device_family, device_model, device_protocol):
        GUI_PORT = 1073

        self.open_socket()

        while self.running:
            discovery_res = f"DLA_DISCOVERY;v1.0;FIN;DeviceName=;DeviceFamily={device_family};IsSimulator=False;" \
                            f"DeviceModelName={device_model};DeviceSerial=C19P00708;MAC=00:07:be:08:8f:e1;ProtocolType={device_protocol};" \
                            f"SwVersion=03.02.00.66;MibSchemaVersion=8.0.0;Status=Running=on-line;" \
                            f"SubnetMask=255.255.255.0;GatewayAddress=192.168.0.1;Dns1Address=8.8.8.8;" \
                            f"Dns2Address=8.8.4.4;UseDhcp=False;SlavesNumber=0;"
            self.sock.sendto(discovery_res.encode('utf-8'), (self.ip_entry.get(), GUI_PORT))
            # print(f"> {discovery_res}")
            time.sleep(1 / 2)


if __name__ == "__main__":
    root = tk.Tk()
    app = DiscoverySimulatorGUI(root)
    root.mainloop()
