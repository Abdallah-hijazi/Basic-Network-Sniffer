import tkinter as tk
from scapy.all import sniff, IP, TCP
import threading
import base64

class NetworkSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")

        # Create a text area for output
        self.text_area = tk.Text(root, height=20, width=80)
        self.text_area.pack(padx=10, pady=5)

        # Create start and stop buttons
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5)
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(side=tk.RIGHT, padx=10, pady=5)

        # Initialize sniffer variables
        self.sniffer_thread = None
        self.is_sniffing = threading.Event()

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
    
            packet_info = f"\nIP Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}\n"
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                packet_info += f"TCP Packet: {tcp_sport} -> {tcp_dport}\n"
                if packet[TCP].payload:
                    payload_data = packet[TCP].payload.load
                    try:
                        tcp_payload_text = payload_data.decode('utf-8')
                        packet_info += f"Text Payload: {tcp_payload_text}\n"
                    except UnicodeDecodeError:
                        hex_payload = payload_data.hex()
                        packet_info += f"Hex Payload: {hex_payload}\n"
                        binary_payload = ' '.join(format(byte, '08b') for byte in payload_data)
                        packet_info += f"Binary Payload: {binary_payload}\n"
                        base64_payload = base64.b64encode(payload_data).decode('utf-8')
                        packet_info += f"Base64 Payload: {base64_payload}\n"
            self.text_area.insert(tk.END, packet_info)


    def start_sniffing(self):
        self.text_area.delete(1.0, tk.END)  # Clear the text area
        self.is_sniffing.set()  # Signal the start of sniffing
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.is_sniffing.clear()  # Signal the stop of sniffing

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda p: not self.is_sniffing.is_set())

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferApp(root)
    root.mainloop()
