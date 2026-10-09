
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def analyze_capture(file_path):
    print("=== Network Packet Analyzer ===")
    print(f"Capture file: {file_path}")

    try:
        packets = rdpcap(file_path)
    except (OSError, ValueError) as error:
        print(f"Could not read capture file: {error}")
        return

    protocol_counts = Counter()
    source_ips = Counter()
    destination_ips = Counter()

    for packet in packets:
        if IP in packet:
            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

            if TCP in packet:
                protocol_counts["TCP"] += 1
            elif UDP in packet:
                protocol_counts["UDP"] += 1
            elif ICMP in packet:
                protocol_counts["ICMP"] += 1
            else:
                protocol_counts["Other IP"] += 1
        else:
            protocol_counts["Non-IPv4"] += 1

    print(f"\nTotal packets: {len(packets)}")

    print("\nProtocol summary:")
    for protocol, count in protocol_counts.most_common():
        print(f"  {protocol}: {count}")

    print("\nTop source IP addresses:")
    for address, count in source_ips.most_common(5):
        print(f"  {address}: {count} packet(s)")

    print("\nTop destination IP addresses:")
    for address, count in destination_ips.most_common(5):
        print(f"  {address}: {count} packet(s)")


if __name__ == "__main__":
    path = input("Enter the path to a .pcap or .pcapng file: ").strip()
    analyze_capture(path)
