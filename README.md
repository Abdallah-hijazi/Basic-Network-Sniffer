<h1>Basic Network Sniffer V1.0 </h1> </br>
A simple Python-based network sniffer that captures and analyzes network traffic. This application helps understand how data flows on a network and how network packets are structured. </br></br>
<h2>Features:</h2>
  - Packet Capturing: Capture live network packets in real-time.</br>
  - Packet Analysis: View detailed information about IP and TCP packets, including source & destination IP addresses, protocol, and port numbers.</br>
  - Payload Display: Display payload data in multiple formats:</br>
    • Text: Shows human-readable text if the payload can be decoded as UTF-8.</br>
    • Hexadecimal: Display the payload in hexadecimal format.</br>
    • Binary: Shows the payload as binary data.</br>
    • Base64: Displays the payload encoded in Base64.</br>
</br>
<h2>Installation:</h2>
 <h3> - Prerequisites: </h3>
    • Pyhton 3.x</br>
    • `scapy` library</br>
    • `tkinter` for the graphical user interface</br>
 <h3> - Setup: </h3>
    1. Clone the repository:</br>
      git clone https://github.com/Abdallah-hijazi/Basic-Network-Sniffer.git</br>
    2. Navigate to the project directory:</br>
      cd Basic-Network-Sniffer</br>
    3. Install the required Python packages:</br>
      pip install scapy</br>
    4. Run the application:</br>
      python sniffer.py</br>
