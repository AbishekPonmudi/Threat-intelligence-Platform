# # This code is written by havox
# # Copyrights(2024)@ Under MIT LICENSE
# #Author = Havox

# from scapy.all import sniff

# log_file = "Traffic_log.txt"
# def capture_packets(packet):
#     with open(log_file,"a") as log_capture:
#         log_capture.write(packet.summary() + "\n ")
#     print(packet.summary())

# sniff(prn=capture_packets, store=False)


# This code is written by havox
# Copyrights(2024)@ Under MIT LICENSE
# Author = Havox

# from scapy.all import sniff, IP

# log_file = "Traffic_log.txt"
# blocked_ips = ["192.168.1.1", "10.0.0.2"]  # Add the IPs you want to block

# def capture_packets(packet):
#     if IP in packet:
#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst

#         if src_ip in blocked_ips or dst_ip in blocked_ips:
#             with open(log_file, "a") as log_capture:
#                 log_capture.write(f"Blocked packet: {packet.summary()}\n")
#             print(f"Blocked packet: {packet.summary()}")
#             return  # Do not process further

#     with open(log_file, "a") as log_capture:
#         log_capture.write(packet.summary() + "\n")
#     print(packet.summary())

# sniff(prn=capture_packets, store=False)


"""This code is written by havox
Copyrights(2024)@ Under MIT LICENSE
Author = Havox """

import subprocess
import sys
import os
import ctypes
from scapy.all import sniff, IP 

log_file = "Traffic_log.txt"
blocked_ips = ["10.10.82.159"]  # Initial list of IPs to block
unblocked_ips = ["8.8.8.8"]  # Initial list of IPs to unblock

def is_running_as_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Relaunch the script with administrative privileges."""
    try:
        # Get the script path and its arguments
        script = sys.argv[0]
        params = ' '.join([script] + sys.argv[1:])
        # Run the script with elevated privileges
        subprocess.run(['powershell', 'Start-Process', 'python', f'-ArgumentList "{params}"', '-Verb', 'runAs'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to elevate privileges: {e}")
        sys.exit(1)

def run_netsh_command(command):
    """Run a netsh command."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        print(f"Successfully executed command: {command}")
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Command output: {e.stdout}")
        print(f"Command error: {e.stderr}")
        return None

def block_ip(ip):
    """Block the given IP using Windows Firewall."""
    commands = [
        f'netsh advfirewall firewall add rule name="BLOCK_IP_{ip}" dir=in action=block remoteip={ip}',
        f'netsh advfirewall firewall add rule name="BLOCK_IP_{ip}" dir=out action=block remoteip={ip}'
    ]
    for command in commands:
        result = run_netsh_command(command)
        if result:
            with open(log_file, "a") as log_capture:
                log_capture.write(f"Blocked IP: {ip}\n")
            print(f"Blocked IP: {ip}")

def unblock_ip(ip):
    """Unblock the given IP using Windows Firewall."""
    commands = [
        f'netsh advfirewall firewall delete rule name="BLOCK_IP_{ip}" dir=in',
        f'netsh advfirewall firewall delete rule name="BLOCK_IP_{ip}" dir=out'
    ]
    for command in commands:
        result = run_netsh_command(command)
        if result:
            with open(log_file, "a") as log_capture:
                log_capture.write(f"Unblocked IP: {ip}\n")
            print(f"Unblocked IP: {ip}")

def capture_packets(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if either source or destination IP is in the blocked list
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            with open(log_file, "a") as log_capture:
                log_capture.write(f"Blocked packet: {packet.summary()}\n")
            print(f"Blocked packet: {packet.summary()}")

            # Unblock IPs if they are in the unblocked list
            if src_ip in unblocked_ips:
                unblock_ip(src_ip)
                unblocked_ips.remove(src_ip)
            if dst_ip in unblocked_ips:
                unblock_ip(dst_ip)
                unblocked_ips.remove(dst_ip)

    with open(log_file, "a") as log_capture:
        log_capture.write(packet.summary() + "\n")
    print(packet.summary())

# Check if running as admin
if not is_running_as_admin():
    print("Script is not running as administrator. Attempting to relaunch with elevated privileges...")
    run_as_admin()
    sys.exit(0)

# Block IPs from the block list at startup
for ip in blocked_ips:
    block_ip(ip)

# Unblock IPs from the unblock list at startup
for ip in unblocked_ips:
    unblock_ip(ip)

# Start sniffing traffic
sniff(prn=capture_packets, store=False)
