"""Compare classical and post-quantum signatures.

Measures, for Ed25519 and ML-DSA-44/65/87 (HMAC-SHA256 shown for reference):
  - public key, private key and signature size in bytes
  - how many bytes the signature adds to each HTTP request (base64 header)
  - median time to generate a key, sign and verify
  - median end-to-end request time through the real API (Ed25519 vs ML-DSA-65 vs HMAC)

Usage:  python benchmarks/benchmark.py [--iterations 2000]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import platform
import secrets
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import cryptography  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402

RAW = serialization.Encoding.Raw

# A realistic message: the canonical string of a transfer request.
MESSAGE = (b"POST\n/api/transfer\nmldsa-client\nml-dsa-65\n1764139200\n"
           b"3f2a9c1d8e7b6a5f4e3d2c1b0a998877\n"
           + hashlib.sha256(b'{"from": "alice", "to": "bob", "amount": 10}').hexdigest().encode())

SCHEMES = {
    "Ed25519 (classical)": ed25519.Ed25519PrivateKey,
    "ML-DSA-44 (post-quantum, NIST level 2)": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65 (post-quantum, NIST level 3)": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87 (post-quantum, NIST level 5)": mldsa.MLDSA87PrivateKey,
}


def median_us(fn, n: int) -> float:
    """Median time of fn() in microseconds over n runs (after a short warm-up)."""
    for _ in range(min(50, n)):
        fn()
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1e6)
    return statistics.median(samples)


def bench_primitives(n: int) -> list[dict]:
    rows = []
    for name, cls in SCHEMES.items():
        key = cls.generate()
        pub = key.public_key()
        sig = key.sign(MESSAGE)
        rows.append({
            "scheme": name,
            "public_key": len(pub.public_bytes(RAW, serialization.PublicFormat.Raw)),
            "private_key": len(key.private_bytes_raw()),
            "signature": len(sig),
            "header": len(base64.b64encode(sig)),
            "keygen_us": median_us(cls.generate, max(n // 10, 50)),
            "sign_us": median_us(lambda: key.sign(MESSAGE), n),
            "verify_us": median_us(lambda: pub.verify(sig, MESSAGE), n),
        })

    secret = secrets.token_bytes(32)
    mac = hmac.new(secret, MESSAGE, hashlib.sha256).digest()
    rows.append({
        "scheme": "HMAC-SHA256 (shared secret, reference)",
        "public_key": 0,
        "private_key": 32,
        "signature": len(mac),
        "header": len(base64.b64encode(mac)),
        "keygen_us": median_us(lambda: secrets.token_bytes(32), n),
        "sign_us": median_us(lambda: hmac.new(secret, MESSAGE, hashlib.sha256).digest(), n),
        "verify_us": median_us(lambda: hmac.compare_digest(
            hmac.new(secret, MESSAGE, hashlib.sha256).digest(), mac), n),
    })
    return rows


def bench_requests(n: int) -> list[dict]:
    """Time real signed requests through the API running on localhost."""
    import threading

    from werkzeug.serving import make_server

    from quantumsign.client import SignedClient
    from quantumsign.keys import CLIENTS, ensure_keys
    from quantumsign.server import create_app

    ensure_keys()
    app = create_app()
    app.logger.disabled = True
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"

    rows = []
    for client_id, alg in CLIENTS.items():
        client = SignedClient(url, client_id)
        samples = []
        for _ in range(n):
            start = time.perf_counter()
            resp = client.request("GET", "/api/balances")
            samples.append((time.perf_counter() - start) * 1000)
            assert resp.status_code == 200, resp.text
        body, headers = client.prepare("GET", "/api/balances")
        header_bytes = sum(len(k) + len(v) + 4 for k, v in headers.items())
        rows.append({"alg": alg, "median_ms": statistics.median(samples),
                     "p95_ms": statistics.quantiles(samples, n=20)[18],
                     "auth_header_bytes": header_bytes})
    server.shutdown()
    return rows


def to_markdown(prim: list[dict], reqs: list[dict], n: int) -> str:
    ed = next(r for r in prim if r["scheme"].startswith("Ed25519"))
    out = [
        "# Benchmark results", "",
        f"Run at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} on {platform.system()} "
        f"{platform.machine()}, Python {platform.python_version()}, "
        f"cryptography {cryptography.__version__} (OpenSSL backend). "
        f"Timings are medians over {n} runs.", "",
        "## Sizes (bytes)", "",
        "| Scheme | Public key | Private key* | Signature | Signature as base64 header | Signature vs Ed25519 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in prim:
        ratio = f"{r['signature'] / ed['signature']:.0f}x" if r["public_key"] else "-"
        out.append(f"| {r['scheme']} | {r['public_key'] or '-'} | {r['private_key']} | "
                   f"{r['signature']} | {r['header']} | {ratio} |")
    out += ["",
            "\\* Private keys are stored as 32-byte seeds. An ML-DSA private key expanded "
            "from its seed is much larger (2560 / 4032 / 4896 bytes for ML-DSA-44/65/87).", "",
            "## Speed (microseconds, lower is better)", "",
            "| Scheme | Key generation | Sign | Verify |",
            "| --- | --- | --- | --- |"]
    for r in prim:
        out.append(f"| {r['scheme']} | {r['keygen_us']:.1f} | {r['sign_us']:.1f} | {r['verify_us']:.1f} |")
    out += ["", "## End-to-end signed request through the API (localhost)", "",
            "| Algorithm | Median (ms) | 95th percentile (ms) | Signature headers (bytes) |",
            "| --- | --- | --- | --- |"]
    for r in reqs:
        out.append(f"| {r['alg']} | {r['median_ms']:.2f} | {r['p95_ms']:.2f} | {r['auth_header_bytes']} |")
    out.append("")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--out", default=str(ROOT / "results" / "benchmark.md"))
    args = parser.parse_args()

    report = to_markdown(bench_primitives(args.iterations), bench_requests(args.requests),
                         args.iterations)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(report)
    print(report)
    print(f"Saved to {args.out}")


if __name__ == "__main__":
    main()
