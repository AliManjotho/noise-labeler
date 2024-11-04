# Noise Labeler

## Overview

This project provides a Python-based tool for extracting and analyzing packet attributes from `.pcap` network capture files. It leverages the `pyshark` library to parse packets and extract various attributes related to different network protocols. The extracted data is saved in CSV format for further analysis and visualization.

## Features

The tool extracts the following attributes from the captured packets:

### Ethernet Layer
- **`eth_src`**: Source MAC address.
- **`eth_dst`**: Destination MAC address.
- **`eth_type`**: Ethernet type (e.g., IPv4, ARP).

### IP Layer
- **`ip_src`**: Source IP address.
- **`ip_dst`**: Destination IP address.
- **`ip_version`**: IP version (IPv4 or IPv6).
- **`ip_ttl`**: Time-to-live value.
- **`ip_protocol`**: Protocol used (e.g., TCP, UDP, ICMP).
- **`ip_len`**: Length of the IP packet.
- **`ip_id`**: Identification field.

### TCP Layer
- **`tcp_srcport`**: Source port number.
- **`tcp_dstport`**: Destination port number.
- **`tcp_seq`**: Sequence number.
- **`tcp_ack`**: Acknowledgment number.
- **`tcp_flags`**: TCP flags (e.g., SYN, ACK, FIN).
- **`tcp_window`**: Window size.

### UDP Layer
- **`udp_srcport`**: Source port number.
- **`udp_dstport`**: Destination port number.
- **`udp_length`**: Length of the UDP packet.

### ICMP Layer
- **`icmp_type`**: ICMP type (e.g., echo request, echo reply).
- **`icmp_code`**: ICMP code.

### ARP Layer
- **`arp_opcode`**: ARP operation (request or reply).
- **`arp_src_proto_ipv4`**: Source protocol address.
- **`arp_dst_proto_ipv4`**: Destination protocol address.
- **`arp_src_hw_mac`**: Source hardware address.
- **`arp_dst_hw_mac`**: Destination hardware address.

### QUIC Layer
- **`quic_version`**: Version of the QUIC protocol.
- **`quic_connection_id`**: Connection ID for the QUIC session.
- **`quic_packet_type`**: Type of QUIC packet (e.g., initial, handshake).
- **`quic_length`**: Length of the QUIC packet.
- **`quic_flags`**: Flags associated with the QUIC packet.

