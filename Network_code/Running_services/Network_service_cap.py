import psutil
import time
from tabulate import tabulate
import argparse
import os

def get_size(bytes):
    """
    Returns the size of bytes in a human-readable format.
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}"
        bytes /= 1024

def get_network_usage():
    # Get current network I/O stats
    io_counters = psutil.net_io_counters(pernic=False)
    return io_counters.bytes_sent, io_counters.bytes_recv

def get_process_network_usage(start_time, show_all):
    """
    Returns a list of processes with their network usage.
    """
    process_network_usage = []

    for proc in psutil.process_iter(['pid', 'name', 'create_time', 'io_counters']):
        try:
            pinfo = proc.info
            # Filter out processes that started before the script was run in current mode
            if not show_all and pinfo['create_time'] < start_time:
                continue
            if pinfo['io_counters'] is not None:
                net_io = pinfo['io_counters']
                upload = get_size(net_io[0])  # bytes_sent
                download = get_size(net_io[1])  # bytes_recv
                process_network_usage.append([pinfo['pid'], pinfo['name'], time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pinfo['create_time'])), upload, download])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Sort processes by creation time in descending order (most recent first)
    process_network_usage.sort(key=lambda x: x[2], reverse=True)

    # Remove duplicate processes by PID (only keep the latest one)
    unique_processes = {proc[0]: proc for proc in process_network_usage}
    process_network_usage = list(unique_processes.values())

    return process_network_usage

def main(show_all):
    start_time = time.time()
    old_bytes_sent, old_bytes_recv = get_network_usage()
    time.sleep(1)

    while True:
        bytes_sent, bytes_recv = get_network_usage()
        upload_speed = bytes_sent - old_bytes_sent
        download_speed = bytes_recv - old_bytes_recv

        process_network_usage = get_process_network_usage(start_time, show_all)
        for proc in process_network_usage:
            proc.append(get_size(upload_speed) + "/s")
            proc.append(get_size(download_speed) + "/s")

        # Clear the screen
        os.system('cls' if os.name == 'nt' else 'clear')

        # Print results in tabular format
        print(tabulate(process_network_usage, headers=['pid', 'name', 'create_time', 'Upload', 'Download', 'Upload Speed', 'Download Speed']))

        old_bytes_sent, old_bytes_recv = bytes_sent, bytes_recv
        time.sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Usage Monitor")
    parser.add_argument("--all", action="store_true", help="Show all processes")
    parser.add_argument("--current", action="store_true", help="Show only currently running processes")
    
    args = parser.parse_args()
    
    if args.all:
        show_all = True
    elif args.current:
        show_all = False
    else:
        print("Please provide either --all or --current argument")
        exit(1)

    main(show_all)
