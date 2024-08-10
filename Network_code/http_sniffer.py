import subprocess
import signal
import sys
from mitmproxy import http

# List of domains and URL paths related to ads on YouTube
blocked_domains = ["sydney.bing.com","copilot.microsoft.com","ads.google.com"]
blocked_paths = ["/ads","/hacking", "/@4GSilverAcademy","/@Letmecooksomething","/UC-9-kyTW8ZkZNDHQJ6FgpwQ"]

proxy_enabled = False  # Track if proxy is enabled

def enable_proxy():
    global proxy_enabled
    try:
        # Command to enable proxy settings
        command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
        subprocess.run(command_proxy, shell=True, check=True)

        command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
        subprocess.run(command_enable, shell=True, check=True)

        proxy_enabled = True
    except subprocess.CalledProcessError as e:
        print(f"Failed to enable proxy: {e}")
        sys.exit(1)

def registry_value_exists(key, value):
    command_check = f'reg query "{key}" /v {value}'
    result = subprocess.run(command_check, shell=True, capture_output=True)
    return result.returncode == 0

def disable_proxy():
    global proxy_enabled
    try:
        # Command to disable proxy settings
        proxy_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        if registry_value_exists(proxy_key, "ProxyServer"):
            command_disable_proxy = f'reg delete "{proxy_key}" /v ProxyServer /f'
            subprocess.run(command_disable_proxy, shell=True, check=True)

        if registry_value_exists(proxy_key, "ProxyEnable"):
            command_disable_enable = f'reg delete "{proxy_key}" /v ProxyEnable /f'
            subprocess.run(command_disable_enable, shell=True, check=True)

        proxy_enabled = False
    except subprocess.CalledProcessError as e:
        print(f"Failed to disable proxy: {e}")
        sys.exit(1)

def start_mitmproxy():
    try:
        # Call function to enable proxy settings
        enable_proxy()

        # Start mitmdump with the required options
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
            # Wait for mitmdump to complete
            mitmdump_process.wait()
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Stopping and disabling the server...")
            disable_proxy()
            sys.exit(0)
        finally:
            # Ensure proxy is disabled before exiting
            disable_proxy()
    except Exception as e:
        print(f"Error starting mitmdump: {e}")
        disable_proxy()
        sys.exit(1)

def request(flow: http.HTTPFlow) -> None:
    global blocked_domains, blocked_paths
    
    # Capture request details
    if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
        source_ip, source_port = flow.client_conn.address
        dest_ip, dest_port = flow.server_conn.address
        print("Request Details:")
        print(f"Request URL: {flow.request.pretty_url}")
        print(f"Request Domain: {flow.request.host}")
        print(f"Source Port: {source_port}")
        print(f"Destination IP: {dest_ip}")
        print(f"Destination Port: {dest_port}")

        # Block requests to specified domains or URL paths
        if any(domain in flow.request.host for domain in blocked_domains) or any(path in flow.request.path for path in blocked_paths):
            flow.response = http.HTTPResponse.make(
                403,  # status code
                b"BLOCKED BY ADMIN",  # content
                {"Content-Type": "text/plain"}  # headers
            )
            print(f"Blocked a request to {flow.request.pretty_url}")

def response(flow: http.HTTPFlow) -> None:
    global blocked_domains, blocked_paths
    
    # Capture response details
    if flow.response:
        source_ip, source_port = flow.client_conn.address
        dest_ip, dest_port = flow.server_conn.address
        print("Response Details:")
        print(f"Response URL: {flow.request.pretty_url}")
        print(f"Response Domain: {flow.request.host}")
        print(f"Source Port: {source_port}")
        print(f"Destination IP: {dest_ip}")
        print(f"Destination Port: {dest_port}")

        # Block responses from specified domains or URL paths
        if any(domain in flow.request.host for domain in blocked_domains) or any(path in flow.request.path for path in blocked_paths):
            # Clear the response content to effectively block it
            flow.response.content = b"Access Blocked"

def main():
    # Register signal handler to disable proxy on exit
    signal.signal(signal.SIGINT, lambda sig, frame: disable_proxy() or sys.exit(0))

    # Start mitmproxy
    print("Starting Server...")
    start_mitmproxy()

if __name__ == "__main__":
    main()
