import subprocess
import sys
import re
from mitmproxy import http

# Domain to capture
capture_domain = "mail.google.com"

# Email address to block
blocked_email = ["havox004@gmail.com","shekabi827@gmail.com"]

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
     

    command = ["mitmdump",
            "--set", "connection_strategy=eager",
            "--set", "stream_large_bodies=10m",
            "--set", "console_eventlog_verbosity=error",
            "--set", "ssl_insecure=true",
            "-s", __file__]
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

def block_email_content(content):
    return blocked_email in extract_email_ids(content)

def log_details(flow, data_type):
    source_ip, source_port = flow.client_conn.address
    dest_ip, dest_port = flow.server_conn.address
    
    print(f"{data_type} Details:")
    print(f"{data_type} URL: {flow.request.pretty_url}")
    print(f"{data_type} Domain: {flow.request.host}")
    print(f"Source IP: {source_ip}")
    print(f"Source Port: {source_port}")
    print(f"Destination IP: {dest_ip}")
    print(f"Destination Port: {dest_port}")
    print(f"{data_type} Headers: {flow.request.headers if data_type == 'Request' else flow.response.headers}")

def request(flow: http.HTTPFlow) -> None:
    if capture_domain in flow.request.host:
        log_details(flow, "Request")
        
        if block_email_content(flow.request.get_text()):
            flow.response = http.HTTPResponse.make(
                403,  # status code
                b"Access denied\nEmail from blocked sender.",  # content
                {"Content-Type": "text/plain"}  # headers
            )
            print(f"Blocked email from {blocked_email} in Request")

def response(flow: http.HTTPFlow) -> None:
    if capture_domain in flow.request.host:
        log_details(flow, "Response")
        
        if block_email_content(flow.response.get_text()):
            flow.response.content = b"Access denied\nEmail from blocked sender."
            print(f"Blocked email from {blocked_email} in Response")

def main():
    print("Starting Server...")
    start_mitmproxy()

if __name__ == "__main__":
    main()
