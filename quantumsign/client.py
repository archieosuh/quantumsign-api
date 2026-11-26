"""A client that signs its requests.

Example (with the server running):
    python -m quantumsign.client --client mldsa-client transfer alice bob 25
    python -m quantumsign.client --client ed25519-client balances
"""

from __future__ import annotations

import argparse
import json

import requests

from .keys import CLIENTS, load_client_key
from .signing import signed_headers


class SignedClient:
    def __init__(self, base_url: str, client_id: str, key=None):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.alg = CLIENTS[client_id]
        self.key = key if key is not None else load_client_key(client_id)

    def prepare(self, method: str, path: str, payload: dict | None = None, **overrides):
        """Build (body, headers) for a signed request without sending it."""
        body = json.dumps(payload).encode() if payload is not None else b""
        headers = signed_headers(method, path, body, self.client_id, self.alg,
                                 self.key, **overrides)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        return body, headers

    def send(self, method: str, path: str, body: bytes, headers: dict) -> requests.Response:
        return requests.request(method, self.base_url + path, data=body,
                                headers=headers, timeout=10)

    def request(self, method: str, path: str, payload: dict | None = None) -> requests.Response:
        body, headers = self.prepare(method, path, payload)
        return self.send(method, path, body, headers)


def main():
    parser = argparse.ArgumentParser(description="QuantumSign signed client")
    parser.add_argument("--url", default="http://127.0.0.1:5000")
    parser.add_argument("--client", default="mldsa-client", choices=sorted(CLIENTS))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("balances")
    t = sub.add_parser("transfer")
    t.add_argument("sender")
    t.add_argument("recipient")
    t.add_argument("amount", type=int)
    args = parser.parse_args()

    client = SignedClient(args.url, args.client)
    if args.command == "balances":
        resp = client.request("GET", "/api/balances")
    else:
        resp = client.request("POST", "/api/transfer",
                              {"from": args.sender, "to": args.recipient, "amount": args.amount})
    print(resp.status_code, resp.text)


if __name__ == "__main__":
    main()
