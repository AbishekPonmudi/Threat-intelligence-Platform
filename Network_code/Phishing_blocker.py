import subprocess
import sys
import re
from mitmproxy import http

# Domain to capture
capture_domain = "mail.google.com"

# Email address to block
blocked_email = "shekabi827@gmail.com"

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

def block_email_content(content):
    return blocked_email in extract_email_ids(content)

def block_flow(flow):
    flow.response = http.HTTPResponse.make(
        204,  # status code (No Content)
        b"",  # empty content
        {"Content-Type": "text/plain"}  # headers
    )

def request(flow: http.HTTPFlow) -> None:
    if capture_domain in flow.request.host:
        request_text = flow.request.get_text(strict=False)
        request_headers = str(flow.request.headers)

        if block_email_content(request_text) or block_email_content(request_headers):
            block_flow(flow)

def response(flow: http.HTTPFlow) -> None:
    if capture_domain in flow.request.host:
        response_text = flow.response.get_text(strict=False)
        response_headers = str(flow.response.headers)

        if block_email_content(response_text) or block_email_content(response_headers):
            block_flow(flow)

def main():
    print("Starting Server...")
    start_mitmproxy()

if __name__ == "__main__":
    main()
