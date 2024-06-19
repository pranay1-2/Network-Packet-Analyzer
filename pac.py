from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        if protocol == 6:  # TCP
            protocol_name = "TCP"
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
        else:
            protocol_name = "Other"
        
        print(f"Packet: {ip_src} -> {ip_dst} | Protocol: {protocol_name}")
        if protocol_name in ["TCP", "UDP"]:
            print(f"Payload: {bytes(packet[protocol_name].payload)}")
        print("--------------------------------------------------")

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
