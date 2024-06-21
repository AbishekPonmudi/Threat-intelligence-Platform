
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Capture request URL and domain
    if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
        print(f"Request URL: {{flow.request.pretty_url}}")
        print(f"Request Domain: {{flow.request.host}}")

def response(flow: http.HTTPFlow) -> None:
    # Capture response URL and domain
    if flow.response:
        print(f"Response URL: {{flow.request.pretty_url}}")
        print(f"Response Domain: {{flow.request.host}}")
