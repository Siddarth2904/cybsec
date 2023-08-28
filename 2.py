from scapy.all import sniff, Raw, rdpcap
from scapy.layers.inet import TCP, IP

# Define the output pcap filename
out_pcap = "output.pcap"


def packet_callback(pkt):
    if TCP in pkt:
        protocol = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        packet_time = pkt.time
        source_address = pkt[IP].src
        destination_address = pkt[IP].dst
        data_payload = pkt[TCP].payload

        if isinstance(data_payload, Raw):
            data_payload = data_payload.load.decode('utf-8', 'ignore')

        # print(f"Protocol type: {protocol}")
        # print(
        #     f"TCP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
        # print(f"Source Address: {source_address}")
        # print(f"Destination Address: {destination_address}")
        # print(f"Packet Timestamp: {packet_time}")
        # print(f"Data Payload: {data_payload}")

        # Append the packet to the pcap file
        # wrpcap(out_pcap, pkt, append=True)


packet_count = 10
sniff(iface="Ethernet", filter="tcp", prn=packet_callback,
      count=packet_count, timeout=10)

# Read and print packets from the pcap file
captured_packets = rdpcap(out_pcap)
for pkt in captured_packets:
    print(pkt.show())
