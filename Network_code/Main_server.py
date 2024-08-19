import subprocess
import signal
import sys
from datetime import datetime
from mitmproxy import ctx, http

blocked_domains = ["gemini.google.com","sydney.bing.com","copilot.microsoft.com","ads.google.com","googleads.g.doubleclick.net"]
blocked_paths = ["/ads","/watch?v=oPsxy9JF8FM","/@havox_cybernet"]

proxy_enabled = False  

class Logger:
    def __init__(self):
        self.log_file = open("network_log.txt", "a")

    def log_request(self, flow: http.HTTPFlow) -> None:
        source_ip, source_port = flow.client_conn.address
        dest_ip, dest_port = flow.server_conn.address
        
        log_message = f"======= Request =======\n"
        log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        log_message += f"URL: {flow.request.pretty_url}\n"
        log_message += f"Method: {flow.request.method}\n"
        log_message += f"Host: {flow.request.host}\n"
        log_message += f"Source IP: {source_ip}:{source_port}\n"
        log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
        log_message += f"Port: {flow.request.port}\n"
        log_message += f"Protocol: HTTP\n" 
        log_message += f"Event ID: REQUEST\n"
        log_message += f"Severity Level: Info\n"
        log_message += "=======================\n\n"
        
        print(log_message.strip())
        self.log_file.write(log_message)

    def log_response(self, flow: http.HTTPFlow) -> None:
        source_ip, source_port = flow.client_conn.address
        dest_ip, dest_port = flow.server_conn.address
        
        log_message = f"======= Response =======\n"
        log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        log_message += f"URL: {flow.request.pretty_url}\n"
        log_message += f"Method: {flow.request.method}\n"
        log_message += f"Host: {flow.request.host}\n"
        log_message += f"Source IP: {source_ip}:{source_port}\n"
        log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
        log_message += f"Port: {flow.request.port}\n"
        log_message += f"Protocol: HTTP\n"  # HTTP protocol for all responses
        log_message += f"Event ID: RESPONSE\n"
        log_message += f"Severity Level: Info\n"
        log_message += "=======================\n\n"
        
        print(log_message.strip())
        self.log_file.write(log_message)

    def done(self):
        self.log_file.close()

logger = Logger()

def enable_proxy():
    global proxy_enabled
    try:
        
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
      
        enable_proxy()

        command = [
            "mitmdump",
            "--set", "connection_strategy=eager",
            "--set", "stream_large_bodies=1500b",
            "--set", "console_eventlog_verbosity=error",
            "--set", "ssl_insecure=true",
            "-s", __file__
        ]
        mitmdump_process = subprocess.Popen(command)

        try:

            mitmdump_process.wait()
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Stopping and disabling the server...")
            disable_proxy()
            sys.exit(0)
        finally:
         
            disable_proxy()
    except Exception as e:
        print(f"Error starting mitmdump: {e}")
        disable_proxy()
        sys.exit(1)

def request(flow: http.HTTPFlow) -> None:
    global blocked_domains, blocked_paths
    
    if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
        logger.log_request(flow)

        if any(domain in flow.request.host for domain in blocked_domains) or any(path in flow.request.path for path in blocked_paths):
            with open("web_warning.html", "rb") as f:
                html_content = f.read()
            flow.response = http.HTTPResponse.make(
                403,  
                html_content,  
                {"Content-Type": "text/html"} 
            )
            print(f"Blocked a request to {flow.request.pretty_url}")

def response(flow: http.HTTPFlow) -> None:
    global blocked_domains, blocked_paths
    
    if flow.response:
        logger.log_response(flow)

        if any(domain in flow.request.host for domain in blocked_domains) or any(path in flow.request.path for path in blocked_paths):
            with open("web_warning.html", "rb") as f:
                html_content = f.read()
            flow.response.content = html_content

def main():
    signal.signal(signal.SIGINT, lambda sig, frame: disable_proxy() or sys.exit(0))
    print("Starting Server...")
    start_mitmproxy()

if __name__ == "__main__":
    main()
