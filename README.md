Basic Network Sniffer V1.0
A simple Python-based network sniffer that captures and analyzes network traffic. This application helps understand how data flows on a network and how network packets are structured.
Features:
  - Packet Capturing: Capture live network packets in real-time.
  - Packet Analysis: View detailed information about IP and TCP packets, including source & destination IP addresses, protocol, and port numbers.
  - Payload Display: Display payload data in multiple formats:
    • Text: Shows human-readable text if the payload can be decoded as UTF-8.
    • Hexadecimal: Display the payload in hexadecimal format.
    • Binary: Shows the payload as binary data.
    • Base64: Displays the payload encoded in Base64.

Installation:
  - Prerequisites:
    • Pyhton 3.x
    • `scapy` library
    • `tkinter` for the graphical user interface
  - Setup:
    1. Clone the repository:
      git clone https://github.com/Abdallah-hijazi/Basic-Network-Sniffer.git
    2. Navigate to the project directory:
      cd Basic-Network-Sniffer
    3. Install the required Python packages:
      pip install -r requirements.txt
    4. Run the application:
      python sniffer.py
