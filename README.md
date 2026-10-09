# Network Packet Analyzer

A Python-based cybersecurity project that analyzes saved network packet captures and summarizes network traffic.

## Features

- Reads `.pcap` and `.pcapng` capture files supported by Scapy.
- Counts TCP, UDP, ICMP, and other packet types.
- Displays the top source IP addresses.
- Displays the top destination IP addresses.
- Handles capture-file reading errors.

## Technologies Used

- Python
- Scapy
- Network protocols: TCP, UDP, ICMP, IPv4

## Requirements

- Python 3
- Scapy 2.8.0 or compatible version

## Installation

```bash
python -m pip install scapy
```

## Usage

Run the analyzer:

```bash
python packet_analyzer.py
```

When prompted, enter the path to a saved `.pcap` or `.pcapng` file.

## Testing

Tested with a sample capture containing three packets: one TCP, one UDP, and one ICMP packet.

## Limitations

This version analyzes saved packet captures. Live packet capture is not implemented.

## Disclaimer

Use this tool only on packet captures you own or are authorized to analyze.
