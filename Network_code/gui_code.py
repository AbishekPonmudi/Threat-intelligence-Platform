import os
import time
import psutil
import pandas as pd
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from collections import defaultdict
from threading import Thread
import queue
from scapy.all import *

# Get all network adapter's MAC addresses
all_macs = {iface.mac for iface in ifaces.values()}
connection2pid = {}
pid2traffic = defaultdict(lambda: [0, 0])
global_df = None
is_program_running = True

def get_size(bytes):
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024

def process_packet(packet):
    global pid2traffic
    try:
        packet_connection = (packet.sport, packet.dport)
    except (AttributeError, IndexError):
        pass
    else:
        packet_pid = connection2pid.get(packet_connection)
        if packet_pid:
            if packet.src in all_macs:
                pid2traffic[packet_pid][0] += len(packet)
            else:
                pid2traffic[packet_pid][1] += len(packet)

def get_connections():
    global connection2pid
    while is_program_running:
        for c in psutil.net_connections():
            if c.laddr and c.raddr and c.pid:
                connection2pid[(c.laddr.port, c.raddr.port)] = c.pid
                connection2pid[(c.raddr.port, c.laddr.port)] = c.pid
        time.sleep(1)

def print_pid2traffic():
    global global_df
    processes = []
    for pid, traffic in pid2traffic.items():
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue
        name = p.name()
        try:
            create_time = datetime.fromtimestamp(p.create_time())
        except OSError:
            create_time = datetime.fromtimestamp(psutil.boot_time())
        process = {
            "pid": pid, "name": name, "create_time": create_time, "Upload": traffic[0],
            "Download": traffic[1],
        }
        try:
            process["Upload Speed"] = traffic[0] - global_df.at[pid, "Upload"]
            process["Download Speed"] = traffic[1] - global_df.at[pid, "Download"]
        except (KeyError, AttributeError):
            process["Upload Speed"] = traffic[0]
            process["Download Speed"] = traffic[1]
        processes.append(process)
    df = pd.DataFrame(processes).set_index("pid").sort_values("Download", ascending=False)
    printing_df = df.copy()
    printing_df["Download"] = printing_df["Download"].apply(get_size)
    printing_df["Upload"] = printing_df["Upload"].apply(get_size)
    printing_df["Download Speed"] = printing_df["Download Speed"].apply(get_size).apply(lambda s: f"{s}/s")
    printing_df["Upload Speed"] = printing_df["Upload Speed"].apply(get_size).apply(lambda s: f"{s}/s")
    global_df = df
    return printing_df

def update_gui():
    while is_program_running:
        time.sleep(1)
        df_copy = print_pid2traffic()
        q.put(df_copy)

def update_treeview(df_copy):
    for row in tree.get_children():
        tree.delete(row)
    for index, row in df_copy.iterrows():
        tree.insert("", "end", iid=index, values=(index, row["name"], row["create_time"], row["Upload"], row["Download"], row["Upload Speed"], row["Download Speed"]))

def process_queue():
    while not q.empty():
        df_copy = q.get()
        update_treeview(df_copy)
    root.after(1000, process_queue)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Network Traffic Monitor")

    columns = ("PID", "Name", "Create Time", "Upload", "Download", "Upload Speed", "Download Speed")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
    tree.pack(fill=tk.BOTH, expand=True)

    q = queue.Queue()

    printing_thread = Thread(target=update_gui)
    printing_thread.start()
    connections_thread = Thread(target=get_connections)
    connections_thread.start()

    print("Started sniffing")
    sniff(prn=process_packet, store=False)

    is_program_running = False

    root.after(1000, process_queue)
    root.mainloop()
