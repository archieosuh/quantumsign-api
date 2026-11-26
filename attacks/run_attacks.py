"""Attack the QuantumSign API and record what gets through.

The attacker is a man-in-the-middle: they can see a real signed request on
the wire, copy it, change it and resend it, but they do NOT have the
client's private key or HMAC secret.

Each attack is run against all three signature algorithms, plus a baseline
against /insecure/transfer, which has no protection at all.

Usage
    python attacks/run_attacks.py                    # starts its own server
    python attacks/run_attacks.py --url http://127.0.0.1:5000
    python attacks/run_attacks.py --max-age 5 --wait-replay
        (really waits past the time window before replaying, instead of
         simulating an old request with an old timestamp)
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402

from quantumsign.client import SignedClient  # noqa: E402
from quantumsign.keys import CLIENTS, ensure_keys  # noqa: E402
from quantumsign.signing import signed_headers  # noqa: E402

TRANSFER = {"from": "alice", "to": "bob", "amount": 10}


def start_local_server(max_age: int) -> str:
    """Run the API in a background thread on a free port."""
    from werkzeug.serving import make_server
    from quantumsign.server import create_app

    app = create_app(max_age=max_age)
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}"


class Attacker:
    def __init__(self, url: str, client: SignedClient):
        self.url = url
        self.client = client  # used only to create the "victim's" real traffic

    def bob_balance(self) -> int:
        return self.client.request("GET", "/api/balances").json()["balances"]["bob"]

    def capture(self, payload=TRANSFER, method="POST", path="/api/transfer", **kw):
        """A genuine request from the real client, as seen on the wire."""
        body, headers = self.client.prepare(method, path, payload, **kw)
        return method, path, body, dict(headers)

    def send(self, method, path, body, headers):
        return requests.request(method, self.url + path, data=body,
                                headers=headers, timeout=10)


def run_scenarios(url: str, client_id: str, max_age: int, wait_replay: bool):
    """Return a list of result rows for one algorithm."""
    client = SignedClient(url, client_id)
    atk = Attacker(url, client)
    rows = []

    def record(name, expect_blocked, expected_reason, sender):
        before = atk.bob_balance()
        resp = sender()
        after = atk.bob_balance()
        try:
            reason = resp.json().get("reason", "")
        except ValueError:
            reason = ""
        moved = after - before
        blocked = resp.status_code == 401 and moved == 0
        passed = blocked == expect_blocked and (not expect_blocked or reason == expected_reason)
        rows.append({
            "attack": name,
            "status": resp.status_code,
            "reason": reason or "-",
            "money_moved": moved,
            "outcome": "BLOCKED" if blocked else "ACCEPTED",
            "as_expected": passed,
        })

    # 0. Control: the genuine request should work.
    captured = atk.capture()
    record("Legitimate signed request (control)", False, "", lambda: atk.send(*captured))

    # 1. Replay the exact same request straight away.
    record("Replay: resend captured request immediately", True, "replay",
           lambda: atk.send(*captured))

    # 2. Replay an old request after the time window has passed.
    if wait_replay:
        old = atk.capture()
        print(f"  [{client_id}] waiting {max_age + 2}s to replay an expired request...")
        time.sleep(max_age + 2)
        record(f"Delayed replay: resend after {max_age + 2}s (real wait)", True, "expired",
               lambda: atk.send(*old))
    else:
        old = atk.capture(timestamp=int(time.time()) - (max_age + 60))
        record(f"Delayed replay: request signed {max_age + 60}s ago", True, "expired",
               lambda: atk.send(*old))

    # 3. Tamper with the body: change the amount, keep the signature.
    m, p, body, h = atk.capture()
    evil = json.dumps({**TRANSFER, "amount": 900}).encode()
    record("Tamper: change amount 10 -> 900", True, "bad_signature",
           lambda: atk.send(m, p, evil, h))

    # 4. Reuse a signature from a harmless GET on the transfer endpoint.
    _, _, _, get_headers = atk.capture(payload=None, method="GET", path="/api/balances")
    get_headers["Content-Type"] = "application/json"
    record("Tamper: reuse GET /api/balances signature on POST /api/transfer",
           True, "bad_signature",
           lambda: atk.send("POST", "/api/transfer", json.dumps(TRANSFER).encode(), get_headers))

    # 5. Take an expired request and give it a fresh timestamp.
    m, p, body, h = atk.capture(timestamp=int(time.time()) - (max_age + 60))
    h["X-Timestamp"] = str(int(time.time()))
    record("Tamper: refresh the timestamp on an expired request", True, "bad_signature",
           lambda: atk.send(m, p, body, h))

    # 6. Forge: sign with the attacker's own key but claim to be the client.
    if client.alg == "hmac-sha256":
        fake_key = b"attacker-guessed-secret-000000000"
    elif client.alg == "ed25519":
        fake_key = ed25519.Ed25519PrivateKey.generate()
    else:
        fake_key = mldsa.MLDSA65PrivateKey.generate()
    forged_body = json.dumps(TRANSFER).encode()
    forged = signed_headers("POST", "/api/transfer", forged_body, client_id, client.alg, fake_key)
    forged["Content-Type"] = "application/json"
    record("Forge: sign with attacker's own key", True, "bad_signature",
           lambda: atk.send("POST", "/api/transfer", forged_body, forged))

    # 7. Strip the signature headers entirely.
    m, p, body, h = atk.capture()
    stripped = {"Content-Type": "application/json"}
    record("Strip: remove all signature headers", True, "missing_headers",
           lambda: atk.send(m, p, body, stripped))

    # 8. Downgrade: claim the request uses no algorithm.
    m, p, body, h = atk.capture()
    h["X-Signature-Alg"] = "none"
    record("Downgrade: set X-Signature-Alg to 'none'", True, "wrong_algorithm",
           lambda: atk.send(m, p, body, h))

    return rows


def run_baseline(url: str, client: SignedClient):
    """The same replay and tamper attacks against the unprotected endpoint."""
    atk = Attacker(url, client)
    rows = []
    body = json.dumps(TRANSFER).encode()
    headers = {"Content-Type": "application/json"}

    for name, payload in (
        ("Legitimate request (control)", body),
        ("Replay: resend captured request immediately", body),
        ("Tamper: change amount 10 -> 900", json.dumps({**TRANSFER, "amount": 900}).encode()),
    ):
        before = atk.bob_balance()
        resp = requests.post(url + "/insecure/transfer", data=payload, headers=headers, timeout=10)
        moved = atk.bob_balance() - before
        rows.append({
            "attack": name,
            "status": resp.status_code,
            "reason": "-",
            "money_moved": moved,
            "outcome": "BLOCKED" if moved == 0 else "ACCEPTED",
            "as_expected": moved > 0,  # without protection we expect the attack to work
        })
    return rows


def to_markdown(results: dict[str, list[dict]]) -> str:
    out = ["# Attack results", "",
           f"Run at {time.strftime('%Y-%m-%d %H:%M:%S %Z')}. "
           "`money_moved` is the change in Bob's balance caused by that request.", ""]
    for section, rows in results.items():
        out += [f"## {section}", "",
                "| Attack | HTTP | Reason | Money moved | Outcome | As expected |",
                "| --- | --- | --- | --- | --- | --- |"]
        for r in rows:
            out.append(f"| {r['attack']} | {r['status']} | {r['reason']} | "
                       f"{r['money_moved']} | {r['outcome']} | {'yes' if r['as_expected'] else 'NO'} |")
        out.append("")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", help="target an already-running server")
    parser.add_argument("--max-age", type=int, default=60,
                        help="time window of the local server (must match the target's)")
    parser.add_argument("--wait-replay", action="store_true",
                        help="really wait past the window before the delayed replay")
    parser.add_argument("--out", default=str(ROOT / "results" / "attack_results.md"))
    args = parser.parse_args()

    ensure_keys()
    url = args.url or start_local_server(args.max_age)
    print(f"Target: {url}")

    results = {"Baseline: /insecure/transfer (no protection)":
               run_baseline(url, SignedClient(url, "hmac-client"))}
    for client_id, alg in CLIENTS.items():
        results[f"Protected: /api/transfer with {alg}"] = run_scenarios(
            url, client_id, args.max_age, args.wait_replay)

    report = to_markdown(results)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(report)
    print(report)

    failures = [r for rows in results.values() for r in rows if not r["as_expected"]]
    print(f"{len(failures)} unexpected result(s). Report saved to {args.out}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
