# import os
# import pandas as pd
# import pyshark

# def extract_attributes_from_pcap(pcap_file):
#     # Open the pcap file using pyshark
#     cap = pyshark.FileCapture(pcap_file)
    
#     # List to store extracted attributes
#     attributes_list = []
    
#     # Iterate over each packet in the capture
#     for packet in cap:
#         # Extract desired attributes from each packet
#         # Example: Extracting source IP, destination IP, and protocol
#         try:
#             src_ip = packet.ip.src
#             dst_ip = packet.ip.dst
#             protocol = packet.transport_layer
#             attributes_list.append({'Source IP': src_ip, 'Destination IP': dst_ip, 'Protocol': protocol})
#         except AttributeError:
#             # If the packet does not have the required attributes, skip it
#             continue
    
#     # Close the capture
#     cap.close()
    
#     return attributes_list

# def generate_csv_from_pcap_folder(pcap_folder, csv_folder):
#     # Ensure the csv folder exists
#     os.makedirs(csv_folder, exist_ok=True)
    
#     # Iterate over each pcap file in the folder
#     for filename in os.listdir(pcap_folder):
#         if filename.endswith('.pcap'):
#             pcap_file_path = os.path.join(pcap_folder, filename)
#             attributes = extract_attributes_from_pcap(pcap_file_path)
            
#             # Convert the list of attributes to a DataFrame
#             df = pd.DataFrame(attributes)
            
#             # Define the output CSV file path
#             csv_file_path = os.path.join(csv_folder, f"{os.path.splitext(filename)[0]}.csv")
            
#             # Save the DataFrame to a CSV file
#             df.to_csv(csv_file_path, index=False)

# # Example usage
# pcap_folder = 'dataset/pcap'
# csv_folder = 'dataset/csv'
# generate_csv_from_pcap_folder(pcap_folder, csv_folder)







import os
import pyshark
import pandas as pd

def extract_packet_layers(pcap_file):
    try:
        capture = pyshark.FileCapture(pcap_file)
        attributes = []
        
        for packet in capture:
            packet_info = {}

            # Ethernet layer
            if hasattr(packet, 'eth'):
                packet_info['eth_src'] = packet.eth.src
                packet_info['eth_dst'] = packet.eth.dst
                packet_info['eth_type'] = packet.eth.type
            
            # IP layer
            if hasattr(packet, 'ip'):
                packet_info['ip_src'] = packet.ip.src
                packet_info['ip_dst'] = packet.ip.dst
                packet_info['ip_version'] = packet.ip.version
                packet_info['ip_ttl'] = packet.ip.ttl
                packet_info['ip_protocol'] = packet.ip.proto
                packet_info['ip_len'] = packet.ip.len
                packet_info['ip_id'] = packet.ip.id
            
            
            # TCP layer
            if hasattr(packet, 'tcp'):
                packet_info['tcp_srcport'] = packet.tcp.srcport
                packet_info['tcp_dstport'] = packet.tcp.dstport
                packet_info['tcp_seq'] = packet.tcp.seq
                packet_info['tcp_ack'] = packet.tcp.ack
                packet_info['tcp_flags'] = packet.tcp.flags
                # packet_info['tcp_window'] = packet.tcp.window
            
            # UDP layer
            if hasattr(packet, 'udp'):
                packet_info['udp_srcport'] = packet.udp.srcport
                packet_info['udp_dstport'] = packet.udp.dstport
                packet_info['udp_length'] = packet.udp.length
            
            # ICMP layer
            if hasattr(packet, 'icmp'):
                packet_info['icmp_type'] = packet.icmp.type
                packet_info['icmp_code'] = packet.icmp.code
            
            # ARP layer
            if hasattr(packet, 'arp'):
                packet_info['arp_opcode'] = packet.arp.opcode
                packet_info['arp_src_proto_ipv4'] = packet.arp.src_proto_ipv4
                packet_info['arp_dst_proto_ipv4'] = packet.arp.dst_proto_ipv4
                packet_info['arp_src_hw_mac'] = packet.arp.src_hw_mac
                packet_info['arp_dst_hw_mac'] = packet.arp.dst_hw_mac

            # QUIC layer
            if hasattr(packet, 'quic'):
                packet_info['quic_version'] = packet.quic.version
                packet_info['quic_connection_id'] = packet.quic.connection_id
                packet_info['quic_packet_type'] = packet.quic.packet_type
                packet_info['quic_length'] = packet.quic.length
                packet_info['quic_flags'] = packet.quic.flags

            attributes.append(packet_info)
        
        return attributes
    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")
        return []

def main(pcap_path, csv_path):
    for filename in os.listdir(pcap_path):
        if filename.endswith('.pcap'):
            pcap_file = os.path.join(pcap_path, filename)
            attributes = extract_packet_layers(pcap_file)
            
            if attributes:
                df = pd.DataFrame(attributes)
                csv_filename = filename.replace('.pcap', '.csv')
                csv_file_path = os.path.join(csv_path, csv_filename)
                df.to_csv(csv_file_path, index=False)
                print(f"Saved attributes to {csv_file_path}")

if __name__ == "__main__":
    pcap_path = 'dataset/pcap'
    csv_path = 'dataset/csv'
    main(pcap_path, csv_path)
