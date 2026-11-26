"""Tests for QuantumSign API. Run with:  pytest -q"""

import base64
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quantumsign.keys import CLIENTS, generate_keys, load_client_key, load_server_registry  # noqa: E402
from quantumsign.server import NonceStore, create_app  # noqa: E402
from quantumsign.signing import signed_headers  # noqa: E402

TRANSFER = {"from": "alice", "to": "bob", "amount": 10}


@pytest.fixture(scope="session")
def key_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    generate_keys(d)
    return d


@pytest.fixture
def app(key_dir):
    return create_app(registry=load_server_registry(key_dir), max_age=60)


@pytest.fixture
def http(app):
    return app.test_client()


def signed(key_dir, client_id, method="POST", path="/api/transfer", payload=TRANSFER, **kw):
    body = json.dumps(payload).encode() if payload is not None else b""
    headers = signed_headers(method, path, body, client_id, CLIENTS[client_id],
                             load_client_key(client_id, key_dir), **kw)
    headers["Content-Type"] = "application/json"
    return body, headers


ALL_CLIENTS = pytest.mark.parametrize("client_id", sorted(CLIENTS))


@ALL_CLIENTS
def test_valid_request_accepted(http, key_dir, client_id):
    body, h = signed(key_dir, client_id)
    r = http.post("/api/transfer", data=body, headers=h)
    assert r.status_code == 200
    assert r.json["balances"] == {"alice": 990, "bob": 10}


@ALL_CLIENTS
def test_replay_blocked(http, key_dir, client_id):
    body, h = signed(key_dir, client_id)
    assert http.post("/api/transfer", data=body, headers=h).status_code == 200
    r = http.post("/api/transfer", data=body, headers=h)
    assert r.status_code == 401 and r.json["reason"] == "replay"


@ALL_CLIENTS
def test_expired_request_blocked(http, key_dir, client_id):
    body, h = signed(key_dir, client_id, timestamp=int(time.time()) - 120)
    r = http.post("/api/transfer", data=body, headers=h)
    assert r.status_code == 401 and r.json["reason"] == "expired"


@ALL_CLIENTS
def test_future_timestamp_blocked(http, key_dir, client_id):
    body, h = signed(key_dir, client_id, timestamp=int(time.time()) + 600)
    r = http.post("/api/transfer", data=body, headers=h)
    assert r.json["reason"] == "future_timestamp"


@ALL_CLIENTS
def test_tampered_body_blocked(http, app, key_dir, client_id):
    _, h = signed(key_dir, client_id)
    evil = json.dumps({**TRANSFER, "amount": 900}).encode()
    r = http.post("/api/transfer", data=evil, headers=h)
    assert r.status_code == 401 and r.json["reason"] == "bad_signature"
    assert app.config["LEDGER"].balances["bob"] == 0


@ALL_CLIENTS
def test_tampered_timestamp_blocked(http, key_dir, client_id):
    body, h = signed(key_dir, client_id, timestamp=int(time.time()) - 120)
    h["X-Timestamp"] = str(int(time.time()))
    assert http.post("/api/transfer", data=body, headers=h).json["reason"] == "bad_signature"


@ALL_CLIENTS
def test_signature_bound_to_path(http, key_dir, client_id):
    _, h = signed(key_dir, client_id, method="GET", path="/api/balances", payload=None)
    r = http.post("/api/transfer", data=json.dumps(TRANSFER), headers=h)
    assert r.json["reason"] == "bad_signature"


def test_missing_headers_blocked(http):
    r = http.post("/api/transfer", json=TRANSFER)
    assert r.status_code == 401 and r.json["reason"] == "missing_headers"


def test_unknown_client_blocked(http, key_dir):
    body, h = signed(key_dir, "ed25519-client")
    h["X-Client-Id"] = "mallory"
    assert http.post("/api/transfer", data=body, headers=h).json["reason"] == "unknown_client"


def test_algorithm_downgrade_blocked(http, key_dir):
    body, h = signed(key_dir, "mldsa-client")
    h["X-Signature-Alg"] = "hmac-sha256"
    assert http.post("/api/transfer", data=body, headers=h).json["reason"] == "wrong_algorithm"


def test_garbage_signature_blocked(http, key_dir):
    body, h = signed(key_dir, "ed25519-client")
    h["X-Signature"] = "not base64!!"
    assert http.post("/api/transfer", data=body, headers=h).json["reason"] == "bad_signature"


def test_cross_client_signature_blocked(http, key_dir):
    """An Ed25519 signature presented as if it came from the ML-DSA client."""
    body, h = signed(key_dir, "ed25519-client")
    h["X-Client-Id"] = "mldsa-client"
    h["X-Signature-Alg"] = "ml-dsa-65"
    assert http.post("/api/transfer", data=body, headers=h).json["reason"] == "bad_signature"


def test_rejected_request_does_not_burn_nonce(http, key_dir):
    """A forged request reusing a nonce must not stop the real one going through."""
    body, h = signed(key_dir, "ed25519-client")
    forged = dict(h, **{"X-Signature": base64.b64encode(b"\x00" * 64).decode()})
    assert http.post("/api/transfer", data=body, headers=forged).status_code == 401
    assert http.post("/api/transfer", data=body, headers=h).status_code == 200


def test_insecure_endpoint_is_vulnerable(http):
    """The baseline: with no signing, a replay moves money twice."""
    http.post("/insecure/transfer", json=TRANSFER)
    r = http.post("/insecure/transfer", json=TRANSFER)
    assert r.json["balances"]["bob"] == 20


def test_nonce_store_expires(monkeypatch):
    store = NonceStore(ttl=10)
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    assert store.use("c", "n1") is True
    assert store.use("c", "n1") is False
    now[0] += 11
    assert store.use("c", "n1") is True  # forgotten; the timestamp check covers it by now


def test_metrics_count_rejections(http):
    http.post("/api/transfer", json=TRANSFER)
    assert 'reason="missing_headers"} 1' in http.get("/metrics").get_data(as_text=True)
