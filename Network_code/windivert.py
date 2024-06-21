
"""This code is written by havox
Copyrights(2024)@ Under MIT LICENSE
Author = Havox """

import pydivert

# rules for blocking the http / https v.1,2 , for TCP and UDP
"""This is the custom rules and which can be added as per the 
requirement"""
 
filter_expression = "(tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 80 or tcp.SrcPort == 443) or (udp.DstPort == 80 or udp.DstPort == 443 or udp.SrcPort == 80 or udp.SrcPort == 443)"

with pydivert.WinDivert(filter_expression) as w:
    print("Capturing and displaying comprehensive information from packets...")
    for packet in w:

        packet_content = packet.payload.decode(errors='ignore')
        packet_type = "TCP" if packet.tcp else "UDP"

        tcp_flags = {
            "SYN": packet.tcp.syn,
            "ACK": packet.tcp.ack,
            "FIN": packet.tcp.fin,
            "RST": packet.tcp.rst
        } if packet.tcp else None
        
        print("Packet Type:", packet_type)
        print("Source:", f"{packet.src_addr}:{packet.src_port}")
        print("Destination:", f"{packet.dst_addr}:{packet.dst_port}")
        print("TCP Flags:", tcp_flags)
        print("Header Length:", packet.tcp.header_len if packet.tcp else None)
        print("Packet Length:", packet.ipv4.packet_len if packet.ipv4 else None)
        print("IPv4 Info:", packet.ipv4)
        print("IPv6 Info:", packet.ipv6)
        print("ICMPv6:", packet.icmpv6)
        print("ICMPv4:", packet.icmpv4)
        print("Packet Content:", packet_content)
        
       
        print("="*50)  

from scapy.all import sniff
from scapy.layers.http import HTTPRequest

def extract_url(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(f'HTTP URL: {url}')
    elif packet.haslayer('UDP') and (packet[UDP].dport == 80 or packet[UDP].dport == 443):
        raw_data = packet.load.decode(errors='ignore')
        if 'Host: ' in raw_data:
            url = raw_data.split('Host: ')[1].split('\r\n')[0]
            print(f'UDP URL: {url}')
    elif packet.haslayer('TCP') and (packet[TCP].dport == 80 or packet[TCP].dport == 443):
        raw_data = packet.load.decode(errors='ignore')
        if 'Host: ' in raw_data:
            url = raw_data.split('Host: ')[1].split('\r\n')[0]
            print(f'TCP URL: {url}')

sniff(filter='tcp or udp', prn=extract_url)



