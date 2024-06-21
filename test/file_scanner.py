# This is written by Havox@ CYberNet #
# @CopyRight under MIT LICENCE #
# Author = "@HaVoX#"
# $+++++++++++++++++++++++++++++++++++++++++++++++++++++++$#

import hashlib
import os
import win32com.shell.shell as shell
import sys
from tqdm import tqdm

# Set this code to run as admin
ADMIN = "adadmin"
if sys.argv[-1] != ADMIN:
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:] + [ADMIN])
    shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)

# Load malicious hashes from IDX file
def load_malicious_hashes(file_path):
    malicious_hashes = set()
    try:
        with open(file_path, 'r') as f:
            for line in f:
                hash = line.strip().split('|')[0]
                if hash:
                    malicious_hashes.add(hash)
    except FileNotFoundError:
        print(f"{file_path} not found. Please make sure the file exists.")
    return malicious_hashes

# Calculate the hash of the file in the system with the root files
def cal_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte in iter(lambda: f.read(4096), b""):
                sha256.update(byte)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError) as e:
        print(f"Skipping the file {file_path}: {e}")
        return None

# Scan the files
def scan_file(file_path, malicious_hashes):
    file_hash = cal_hash(file_path)
    if file_hash and file_hash in malicious_hashes:
        return f"Malicious content detected! File location: {file_path}, File hash: {file_hash}"
    return None

# Scan the root directory for the malicious content with file path and hash values from the table or API
def scan_directory(root):
    file_paths = []
    for dirpath, _, filenames in os.walk(root):
        for file in filenames:
            file_paths.append(os.path.join(dirpath, file))
    return file_paths

# Function declared to scan the entire file on the OS. If in nt, get to root directory using '\'
if __name__ == "__main__":
    root_dir = ['C:\\'] if os.name == 'nt' else ['/']
    malicious_hashes = load_malicious_hashes('malicious_hashes.idx')
    total_files = 0
    malicious_count = 0

    # Gather all file paths
    file_paths = []
    for root in root_dir:
        file_paths.extend(scan_directory(root))
    total_files = len(file_paths)

    # Scan files with progress bar
    print("Scanning Files:")
    with tqdm(total=total_files, desc="Progress", unit="file", position=0, leave=True, ncols=100) as pbar:
        for file_path in file_paths:
            result = scan_file(file_path, malicious_hashes)
            if result:
                print(result)
                malicious_count += 1
            pbar.update(1)

    print(f"\nScanning complete. {malicious_count} malicious files detected.")
