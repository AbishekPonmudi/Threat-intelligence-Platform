"""This code is written by havox
Copyrights(2024)@ Under MIT LICENSE
Author = Havox """

import os
import psutil
import time
import sys
import ctypes
import datetime
from collections import defaultdict
from threading import Thread
import pandas as pd
from scapy.all import *

# To collect the MAC addresses using iface by scapy
mac_cap = {iface.mac for iface in ifaces.values()}
connectionpid = {}  # Declaring an empty dictionary for mapping
pidtraffic = defaultdict(lambda: [0, 0])  # Using lambda for upload and download data
running = True

# Declaring the bytes and types
def byte_size(bytes):
    for units in ["", "K", "M", "G", "T"]:
        if bytes < 1024:
            return f"{bytes:.2f}{units}B"
        bytes /= 1024

def running_as_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    try:
        code = sys.argv[0]  # Get the file name
        shellcode = ''.join([code] + sys.argv[1:])
        subprocess.run(['powershell', 'start-process', 'python', '-ArgumentList', f"{shellcode}", '-verb', 'runas'], check=True)
    except:
        sys.exit(1)

def process_packet(packet):
    try:
        packet_connection = (packet.sport, packet.dport)
    except (AttributeError, IndexError):
        print("Some error occurred")
        pass
    else:
        packet_pid = connectionpid.get(packet_connection)
        if packet_pid:
            if packet.src in mac_cap:
                pidtraffic[packet_pid][0] += len(packet)
            else:
                pidtraffic[packet_pid][1] += len(packet)

def get_connection():
    while running:
        for c in psutil.net_connections():
            if c.laddr and c.raddr:
                connectionpid[(c.laddr.port, c.raddr.port)] = c.pid
                connectionpid[(c.raddr.port, c.laddr.port)] = c.pid
        time.sleep(1)

def print_pidtraffic():
    global global_df
    processes = []
    for pid, traffic in pidtraffic.items():
        try:
            p2id = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue
        name = p2id.name()
        
        try:
            create_time = datetime.fromtimestamp(p2id.create_time())
        except OSError:
            create_time = datetime.fromtimestamp(psutil.boot_time())
            
        process = {
            "Pid": pid, "Name": name, "Created_time": create_time,
            "Upload": traffic[0], "Download": traffic[1]
        }
        try:
            process["Upload_speed"] = traffic[0] - global_df.at[pid, "Upload"]
            process["Download_speed"] = traffic[1] - global_df.at[pid, "Download"]
        except (KeyError, AttributeError):
            process["Upload_speed"] = traffic[0]
            process["Download_speed"] = traffic[1]
            
        processes.append(process)  
    
    df = pd.DataFrame(processes)
    try:
        df = df.set_index("Pid")
        df.sort_values("Download", inplace=True, ascending=False)
    except KeyError as e:
        pass

    printing_df = df.copy()
    try:
        printing_df["Download"] = printing_df["Download"].apply(byte_size)
        printing_df["Upload"] = printing_df["Upload"].apply(byte_size)
        printing_df["Download_speed"] = printing_df["Download_speed"].apply(byte_size).apply(lambda s: f"{s}/s")
        printing_df["Upload_speed"] = printing_df["Upload_speed"].apply(byte_size).apply(lambda s: f"{s}/s")
    except KeyError as e:
        pass

    os.system('cls' if os.name == 'nt' else 'clear')
    print(printing_df.to_string())
    global_df = df

def print_stats():
    while running:
        time.sleep(1)
        print_pidtraffic()

if __name__ == "__main__":
    printing_thread = Thread(target=print_stats)
    printing_thread.start()
   
    connections_thread = Thread(target=get_connection)
    connections_thread.start()

    print("Started sniffing")
    sniff(prn=process_packet, store=False)
    running = False   
