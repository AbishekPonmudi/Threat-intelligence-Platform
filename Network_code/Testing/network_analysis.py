import dpkt
import pcap
import datetime

def packet_capture(timestamp, data):
    try:
        eth = dpkt.ethernet.Ethernet(data)
    except dpkt.UnpackError:
        print("Failed to unpack Ethernet frame")
        return

    log_lines = []

    timestamp_str = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    log_lines.append(f"Timestamp: {timestamp_str}")

    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        tcp = ip.data

        log_lines.append(f"Source IP: {dpkt.utils.inet_to_str(ip.src)}")
        log_lines.append(f"Destination IP: {dpkt.utils.inet_to_str(ip.dst)}")

        if isinstance(tcp, dpkt.tcp.TCP):
            log_lines.append("TCP packet")
            log_lines.append(f"Source port: {tcp.sport}")
            log_lines.append(f"Destination port: {tcp.dport}")
        elif isinstance(tcp, dpkt.udp.UDP):
            log_lines.append("UDP packet")
            log_lines.append(f"Source port: {tcp.sport}")
            log_lines.append(f"Destination port: {tcp.dport}")
        else:
            log_lines.append("Unknown transport protocol")
    elif isinstance(eth.data, dpkt.arp.ARP):
        arp = eth.data
        log_lines.append(f"ARP Packet: {arp}")
    elif isinstance(eth.data, dpkt.igmp.IGMP):
        igmp = eth.data
        log_lines.append(f"IGMP Packet: {igmp}")
    else:
        log_lines.append("Unknown packet type")

    log_file = "Network_log.txt"
    with open(log_file, "a") as f:
        for line in log_lines:
            f.write(line + "\n")
        f.write("\n")

    print(f"Timestamp: {timestamp_str}")

    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        tcp = ip.data

        print(f"Source IP: {dpkt.utils.inet_to_str(ip.src)}")
        print(f"Destination IP: {dpkt.utils.inet_to_str(ip.dst)}")

        if isinstance(tcp, dpkt.tcp.TCP):
            print("TCP packet")
            print(f"Source port: {tcp.sport}")
            print(f"Destination port: {tcp.dport}")
        elif isinstance(tcp, dpkt.udp.UDP):
            print("UDP packet")
            print(f"Source port: {tcp.sport}")
            print(f"Destination port: {tcp.dport}")
        else:
            print("Unknown transport protocol")
    elif isinstance(eth.data, dpkt.arp.ARP):
        arp = eth.data
        print(f"ARP Packet: {arp}")
    elif isinstance(eth.data, dpkt.igmp.IGMP):
        igmp = eth.data
        print(f"IGMP Packet: {igmp}")
    else:
       print("Unknown packet type")

try:
    out = pcap.pcap()
    out.loop(0, packet_capture)
except PermissionError:
    print("Permission denied: You need to run this script with elevated privileges.")
except Exception as e:
    print(f"An error occurred: {e}")
