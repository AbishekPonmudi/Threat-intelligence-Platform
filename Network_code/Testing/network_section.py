import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import pandas as pd
import time
from collections import defaultdict


# add = lambda a,b : a+ b   
# print(add(10,20))

# Initialize lists and dictionaries to store packet details and connection statuses
packet_info_list = []
connection_status = defaultdict(lambda: 'UNKNOWN')
ip_request_count = defaultdict(int)
session_data = defaultdict(list)

def packet_callback(packet):
    packet_info = {}
    
    if packet.haslayer(scapy.IP):
        packet_info['src_ip'] = packet[scapy.IP].src
        packet_info['dst_ip'] = packet[scapy.IP].dst
        ip_request_count[packet[scapy.IP].src] += 1
    if packet.haslayer(scapy.TCP):
        packet_info['src_port'] = packet[scapy.TCP].sport
        packet_info['dst_port'] = packet[scapy.TCP].dport
        
    # capture the request  

    if packet.haslayer(HTTPRequest):
        packet_info['method'] = packet[HTTPRequest].Method.decode()
        packet_info['host'] = packet[HTTPRequest].Host.decode()
        packet_info['path'] = packet[HTTPRequest].Path.decode()
        packet_info['http_version'] = packet[HTTPRequest].Http_Version.decode()
        packet_info['is_request'] = True


        session_key = (packet[scapy.IP].src, packet[scapy.TCP].sport, packet[HTTPRequest].Host.decode())
        session_data[session_key].append(packet_info)

    if packet.haslayer(HTTPResponse):
        packet_info['status_code'] = packet[HTTPResponse].Status_Code.decode()
        packet_info['reason_phrase'] = packet[HTTPResponse].Reason_Phrase.decode()
        packet_info['is_request'] = False

        session_key = (packet[scapy.IP].dst, packet[scapy.TCP].dport, packet[scapy.HTTPResponse].Host.decode())
        if session_key in session_data:
            session_data[session_key].append(packet_info)

    if packet.haslayer(scapy.DNS):
        packet_info['dns_qry_name'] = packet[scapy.DNSQR].qname.decode()
        packet_info['dns_response'] = packet[scapy.DNSRR].rdata if packet.haslayer(scapy.DNSRR) else 'N/A'
    
    # Connection status
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].flags == 'S':
            connection_status[packet[scapy.IP].src] = 'SYN_SENT'
        elif packet[scapy.TCP].flags == 'SA':
            connection_status[packet[scapy.IP].src] = 'SYN_ACK_RECEIVED'
        elif packet[scapy.TCP].flags == 'F':
            connection_status[packet[scapy.IP].src] = 'FINISHED'
        elif packet[scapy.TCP].flags == 'R':
            connection_status[packet[scapy.IP].src] = 'RESET'
    
    packet_info_list.append(packet_info)

# Capture packets in real-time
try:
    print("Starting packet capture... Press Ctrl+C to stop.")
    scapy.sniff(prn=packet_callback, store=False)
except KeyboardInterrupt:
    print("Packet capture stopped.")

# Process sessions for saving
session_info_list = []
for session_key, packets in session_data.items():
    request_info = None
    response_info = None
    for packet in packets:
        if packet.get('is_request'):
            request_info = packet
        else:
            response_info = packet
        if request_info and response_info:
            session_info = {
                'src_ip': session_key[0],
                'src_port': session_key[1],
                'host': session_key[2],
                'method': request_info['method'],
                'path': request_info['path'],
                'http_version': request_info['http_version'],
                'status_code': response_info['status_code'],
                'reason_phrase': response_info['reason_phrase'],
                'connection_status': connection_status[session_key[0]],
                'request_count': ip_request_count[session_key[0]]
            }
            session_info_list.append(session_info)
            request_info = None
            response_info = None

# Convert the list of session details to a DataFrame
df = pd.DataFrame(session_info_list)

# Save to a CSV file for further analysis
timestamp = int(time.time())
df.to_csv(f'network_sessions_{timestamp}.csv', index=False)

print("Session details saved to CSV file.")
