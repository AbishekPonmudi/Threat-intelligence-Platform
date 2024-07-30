import subprocess
import sys
import re
from mitmproxy import http

# Domains to capture
capture_domains = ["mail.google.com", "protonmail.com"]
log_file = "captured_emails.log"

proxy_enabled = False  # Track if proxy is enabled

def enable_proxy():
    global proxy_enabled
    command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
    subprocess.run(command_proxy, shell=True, check=True)

    command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
    subprocess.run(command_enable, shell=True, check=True)

    proxy_enabled = True

def disable_proxy():
    global proxy_enabled
    command_disable = r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f'
    subprocess.run(command_disable, shell=True, check=True)

    command_disable = r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /f'
    subprocess.run(command_disable, shell=True, check=True)

    proxy_enabled = False

def start_mitmproxy():
    enable_proxy()

    command = [
        "mitmdump",
        "--set", "connection_strategy=eager",
        "--set", "stream_large_bodies=10m",
        "--set", "console_eventlog_verbosity=error",
        "--set", "ssl_insecure=true",
        "-s", __file__
    ]
    mitmdump_process = subprocess.Popen(command)

    try:
        mitmdump_process.wait()
    except KeyboardInterrupt:
        print("\nCtrl+C detected. Stopping and disabling the server...")
    finally:
        disable_proxy()
        sys.exit(0)

def extract_email_ids(content):
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, content)

def log_email(domain, email):
    with open(log_file, 'a') as f:
        f.write(f"{domain}: {email}\n")

def process_flow(flow, data):
    for domain in capture_domains:
        if domain in flow.request.host:
            emails = extract_email_ids(data)
            if emails:
                for email in emails:
                    log_email(domain, email)

def request(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.host for domain in capture_domains):
        process_flow(flow, flow.request.get_text())

def response(flow: http.HTTPFlow) -> None:
    if any(domain in flow.request.host for domain in capture_domains):
        process_flow(flow, flow.response.get_text())

def main():
    print("Starting Server...")
    start_mitmproxy()

if __name__ == "__main__":
    main()
