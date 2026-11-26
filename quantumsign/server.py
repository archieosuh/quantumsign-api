"""The QuantumSign API server (Flask).

Endpoints
    GET  /health              open, for checks
    GET  /metrics             open, Prometheus-style counters of accepted/rejected requests
    GET  /api/balances        signed requests only
    POST /api/transfer        signed requests only, moves money between accounts
    POST /insecure/transfer   NO protection; the baseline the attacks are compared with

Run it with:  python -m quantumsign.server
"""

from __future__ import annotations

import base64
import binascii
import threading
import time
from collections import Counter
from functools import wraps

from flask import Flask, g, jsonify, request

from .keys import ensure_keys, load_server_registry
from .signing import SIGNATURE_HEADERS, canonical_string, verify

DEFAULT_MAX_AGE = 60  # seconds a signed request stays valid


class NonceStore:
    """Remembers nonces it has seen until they are too old to matter.

    A nonce only needs keeping for as long as its timestamp would still pass
    the age check. After that the timestamp check rejects the request anyway.
    In production this would live in Redis with a TTL so that every server
    instance shares it; an in-memory dict is fine for one process.
    """

    def __init__(self, ttl: int):
        self.ttl = ttl
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def use(self, client_id: str, nonce: str) -> bool:
        """Record the nonce. Return False if it was already used."""
        now = time.time()
        with self._lock:
            # Forget expired nonces so memory doesn't grow forever.
            for key in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[key]
            key = (client_id, nonce)
            if key in self._seen:
                return False
            self._seen[key] = now + self.ttl
            return True


class Ledger:
    """A tiny in-memory bank, so a successful attack has a visible effect."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.balances = {"alice": 1000, "bob": 0}

    def transfer(self, sender: str, recipient: str, amount: int) -> None:
        with self._lock:
            if sender not in self.balances or recipient not in self.balances:
                raise ValueError("unknown account")
            if amount <= 0:
                raise ValueError("amount must be positive")
            if self.balances[sender] < amount:
                raise ValueError("insufficient funds")
            self.balances[sender] -= amount
            self.balances[recipient] += amount


def create_app(registry: dict | None = None, max_age: int = DEFAULT_MAX_AGE) -> Flask:
    app = Flask(__name__)

    if registry is None:
        ensure_keys()
        registry = load_server_registry()

    nonces = NonceStore(ttl=max_age * 2)
    ledger = Ledger()
    metrics: Counter = Counter()
    app.config.update(REGISTRY=registry, MAX_AGE=max_age, LEDGER=ledger, NONCES=nonces)

    def reject(reason: str, detail: str):
        metrics[f"rejected:{reason}"] += 1
        app.logger.warning("REJECTED reason=%s client=%s path=%s detail=%s",
                           reason, request.headers.get("X-Client-Id", "-"),
                           request.path, detail)
        return jsonify(error=detail, reason=reason), 401

    def require_signature(view):
        """Decorator: only run the view if the request is correctly signed."""

        @wraps(view)
        def wrapper(*args, **kwargs):
            h = request.headers

            # 1. Every signature header must be there.
            missing = [name for name in SIGNATURE_HEADERS if not h.get(name)]
            if missing:
                return reject("missing_headers", f"missing headers: {', '.join(missing)}")

            client_id = h["X-Client-Id"]
            alg = h["X-Signature-Alg"]
            ts_raw = h["X-Timestamp"]
            nonce = h["X-Nonce"]

            # 2. The client must be known, and must use the algorithm registered
            #    for it. This blocks "downgrade" tricks like claiming alg=none.
            client = registry.get(client_id)
            if client is None:
                return reject("unknown_client", "unknown client")
            if alg != client["alg"]:
                return reject("wrong_algorithm", "algorithm does not match this client")

            # 3. The timestamp must be recent (and not far in the future).
            try:
                ts = int(ts_raw)
            except ValueError:
                return reject("bad_timestamp", "timestamp is not a number")
            age = time.time() - ts
            if age > max_age:
                return reject("expired", f"request is {int(age)}s old (limit {max_age}s)")
            if age < -max_age:
                return reject("future_timestamp", "timestamp is in the future")

            # 4. The signature must match the canonical string of THIS request.
            try:
                signature = base64.b64decode(h["X-Signature"], validate=True)
            except (binascii.Error, ValueError):
                return reject("bad_signature", "signature is not valid base64")
            message = canonical_string(request.method, request.path, client_id,
                                       alg, ts_raw, nonce, request.get_data(cache=True))
            if not verify(alg, client["key"], message, signature):
                return reject("bad_signature", "signature check failed")

            # 5. The nonce must be new. Checked only after the signature passes,
            #    so attackers can't fill the store with junk nonces.
            if not nonces.use(client_id, nonce):
                return reject("replay", "replay detected: nonce already used")

            metrics[f"accepted:{alg}"] += 1
            g.client_id = client_id
            return view(*args, **kwargs)

        return wrapper

    def do_transfer():
        data = request.get_json(silent=True) or {}
        try:
            ledger.transfer(str(data.get("from")), str(data.get("to")), int(data.get("amount", 0)))
        except (ValueError, TypeError) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(status="ok", balances=ledger.balances)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/metrics")
    def metrics_endpoint():
        lines = ["# TYPE quantumsign_requests_total counter"]
        for key, value in sorted(metrics.items()):
            outcome, label = key.split(":", 1)
            name = "alg" if outcome == "accepted" else "reason"
            lines.append(f'quantumsign_requests_total{{outcome="{outcome}",{name}="{label}"}} {value}')
        return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}

    @app.get("/api/balances")
    @require_signature
    def balances():
        return jsonify(balances=ledger.balances, client=g.client_id)

    @app.post("/api/transfer")
    @require_signature
    def transfer():
        return do_transfer()

    @app.post("/insecure/transfer")
    def insecure_transfer():
        return do_transfer()

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000)
