"""Small standard-library client for the SecureSense REST API."""
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE_URL = os.environ.get("SECURESENSE_API_URL", "http://127.0.0.1:8001").rstrip("/")
TOKEN = os.environ.get("SECURESENSE_API_TOKEN")

def request_json(path: str, method: str = "GET", payload: dict | None = None) -> object:
    headers = {"Accept": "application/json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    with urlopen(request, timeout=10) as response:
        content = response.read()
        return json.loads(content) if content else {}

def main() -> int:
    try:
        print("Health:", request_json("/health"))
        if not TOKEN:
            print("Set SECURESENSE_API_TOKEN to call protected endpoints.")
            return 1
        print("Registered devices:", request_json("/devices"))
        print("Latest sensor readings:", request_json("/telemetry/latest"))
        print("Client setup and API access verified.")
        print("No investigation was submitted; this example is read-only.")
        return 0
    except HTTPError as exc:
        print(f"HTTP error: {exc.code} {exc.reason}", file=sys.stderr)
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
    return 1

if __name__ == "__main__":
    sys.exit(main())
