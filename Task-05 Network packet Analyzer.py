from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to analyze and display packet information
def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Check if the protocol is TCP, UDP, or ICMP
        if packet.haslayer(TCP):
            print(f"TCP Packet: {ip_src} -> {ip_dst} (Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport})")
        elif packet.haslayer(UDP):
            print(f"UDP Packet: {ip_src} -> {ip_dst} (Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport})")
        elif packet.haslayer(ICMP):
            print(f"ICMP Packet: {ip_src} -> {ip_dst} (Type: {packet[ICMP].type})")
        else:
            print(f"Other Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")
        
        # Display the payload if any
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload Data: {payload[:50]}...")  # Display first 50 bytes of the payload

# Start sniffing network packets
print("Starting packet capture. Press CTRL+C to stop.")
sniff(prn=analyze_packet, store=0)
