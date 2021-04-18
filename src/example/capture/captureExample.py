from scapy.all import IP, rdpcap

file = rdpcap("TeamSpeak2.pcap")

for count, packet in enumerate(file, 1):
    print("Packet", count)
    print("Got a packet going from", packet[IP].src, "to", packet[IP].dst)
