# """This code is written by Havox
# Copyrights(2024)@ Under MIT LICENSE
# Author = Havox """

# #  WORKING CODE ONLY FOR SNIFF URL 


# # import subprocess
# # from mitmproxy import http

# # def start_mitmproxy():
# #     command = ["mitmdump", "-s", "DOMAIN_GEN_AL.py"]
# #     subprocess.run(command)

# # def request(flow: http.HTTPFlow) -> None:
# #     # Capture request URL, domain, source IP, and port
# #     if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
# #         source_ip, source_port = flow.client_conn.address
# #         dest_ip, dest_port = flow.server_conn.address
# #         print(f"Request URL: {flow.request.pretty_url}")
# #         print(f"Request Domain: {flow.request.host}")

# # def response(flow: http.HTTPFlow) -> None:
# #     # Capture response URL, domain, source IP, and port
# #     if flow.response:
# #         source_ip, source_port = flow.client_conn.address
# #         dest_ip, dest_port = flow.server_conn.address
# #         print(f"Response URL: {flow.request.pretty_url}")
# #         print(f"Response Domain: {flow.request.host}")

# # if __name__ == "__main__":
# #     print("Starting Https sniff...")
# #     start_mitmproxy()


# # """This code is written by Havox
# # Copyrights(2024)@ Under MIT LICENSE
# # Author = Havox """

# # import subprocess
# # from mitmproxy import http

# # blocked_domains = ["youtube.com","google.com","google.co.in"]

# # def start_mitmproxy():
# #     command = ["mitmdump", "-s", __file__]
# #     subprocess.run(command)

# # def request(flow: http.HTTPFlow) -> None:
# #     global blocked_domains
    
# #     # Capture request details
# #     if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
# #         source_ip, source_port = flow.client_conn.address
# #         dest_ip, dest_port = flow.server_conn.address
# #         print("Request Details:")
# #         print(f"Request URL: {flow.request.pretty_url}")
# #         print(f"Request Domain: {flow.request.host}")
# #         print(f"Source IP: {source_ip}")
# #         print(f"Source Port: {source_port}")
# #         print(f"Destination IP: {dest_ip}")
# #         print(f"Destination Port: {dest_port}")

# #         # Block requests to specified domains
# #         if any(domain in flow.request.pretty_url for domain in blocked_domains):
# #             flow.response = http.HTTPResponse.make(
# #                 403,  # status code
# #                 b"Blocked By Admin",  # content
# #                 {"Content-Type": "text/plain"}  # headers
# #             )
# #             print(f"Blocked a request to {flow.request.host}")

# # def response(flow: http.HTTPFlow) -> None:
# #     global blocked_domains
    
# #     # Capture response details
# #     if flow.response:
# #         source_ip, source_port = flow.client_conn.address
# #         dest_ip, dest_port = flow.server_conn.address
# #         print("Response Details:")
# #         print(f"Response URL: {flow.request.pretty_url}")
# #         print(f"Response Domain: {flow.request.host}")
# #         print(f"Source IP: {source_ip}")
# #         print(f"Source Port: {source_port}")
# #         print(f"Destination IP: {dest_ip}")
# #         print(f"Destination Port: {dest_port}")

# #         # Block responses from specified domains
# #         if any(domain in flow.request.pretty_url for domain in blocked_domains):
# #             # Clear the response content to effectively block it
# #             flow.response.content = b"Blocked By Admin' "

# # if __name__ == "__main__":
# #     print("Starting mitmproxy...")
# #     start_mitmproxy()
 
# import subprocess
# import signal
# import sys
# from mitmproxy import http

# blocked_domains = ["gemini.google.com", "google.co.in"]
# proxy_enabled = False  # Track if proxy is enabled

# def enable_proxy():
#     global proxy_enabled
#     # Command to enable proxy settings
#     command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
#     subprocess.run(command_proxy, shell=True, check=True)

#     command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
#     subprocess.run(command_enable, shell=True, check=True)

#     proxy_enabled = True

# def disable_proxy():
#     global proxy_enabled
#     # Command to disable proxy settings
#     command_disable = r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f'
#     subprocess.run(command_disable, shell=True, check=True)

#     command_disable = r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /f'
#     subprocess.run(command_disable, shell=True, check=True)

#     proxy_enabled = False

# def start_mitmproxy():
#     # Call function to enable proxy settings
#     enable_proxy()

#     # Start mitmdump
#     command = ["mitmdump", "-s", __file__]
#     mitmdump_process = subprocess.Popen(command)

#     try:
#         # Wait for mitmdump to complete
#         mitmdump_process.wait()
#     except KeyboardInterrupt:
#         print("\nCtrl+C detected. Stopping and disabiling the server...")
#         disable_proxy()
#         sys.exit(0)
#     finally:
#         # Ensure proxy is disabled before exiting
#         disable_proxy()

# def request(flow: http.HTTPFlow) -> None:
#     global blocked_domains
    
#     # Capture request details
#     if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
#         print("Request Details:")
#         print(f"Request URL: {flow.request.pretty_url}")
#         print(f"Request Domain: {flow.request.host}")
#         print(f"Source Port: {source_port}")
#         print(f"Destination IP: {dest_ip}")
#         print(f"Destination Port: {dest_port}")

#         # Block requests to specified domains
#         if any(domain in flow.request.pretty_url for domain in blocked_domains):
#             flow.response = http.HTTPResponse.make(
#                 403,  # status code
#                 b"BLOCKED BY ADMIN",  # content
#                 {"Content-Type": "text/plain"}  # headers
#             )
#             print(f"Blocked a request to {flow.request.host}")

# def response(flow: http.HTTPFlow) -> None:
#     global blocked_domains
    
#     # Capture response details
#     if flow.response:
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
#         print("Response Details:")
#         print(f"Response URL: {flow.request.pretty_url}")
#         print(f"Response Domain: {flow.request.host}")
#         print(f"Source Port: {source_port}")
#         print(f"Destination IP: {dest_ip}")
#         print(f"Destination Port: {dest_port}")

#         # Block responses from specified domains
#         if any(domain in flow.request.pretty_url for domain in blocked_domains):
#             # Clear the response content to effectively block it
#             flow.response.content = b"BLOCKED BY ADMIN"

# def main():
#     # Start mitmproxy
#     print("Starting Server...")
#     start_mitmproxy()

# if __name__ == "__main__":
#     main()

import subprocess
import signal
import sys
from mitmproxy import http

# List of domains and URL paths related to ads on YouTube
blocked_domains = [ "gemini.google.com", "google.com","sydney.bing.com"]
blocked_paths = ["/ads","/watch?v=Qyd5Wz_Zst4&ab_channel"]

proxy_enabled = False  # Track if proxy is enabled

def enable_proxy():
    global proxy_enabled
    # Command to enable proxy settings
    command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
    subprocess.run(command_proxy, shell=True, check=True)

    command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
    subprocess.run(command_enable, shell=True, check=True)

    proxy_enabled = True

def disable_proxy():
    global proxy_enabled
    # Command to disable proxy settings
    command_disable = r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f'
    subprocess.run(command_disable, shell=True, check=True)

    command_disable = r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /f'
    subprocess.run(command_disable, shell=True, check=True)

    proxy_enabled = False

def start_mitmproxy():
    # Call function to enable proxy settings
    enable_proxy()

    # Start mitmdump
    command = ["mitmdump", "-s", __file__]
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
                b"Access denied\nYou are not allowed to execute the action you have requested.",  # content
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
            flow.response.content = b"Access denied \nYou are not allowed to execute the action you have requested."

def main():
    # Start mitmproxy
    print("Starting Server...")
    start_mitmproxy()

if __name__ == "__main__":
    main()
