# QuantumSign API

A small Python API protected by **signed requests**. I attacked it with replay and tampering attacks, then added a **post-quantum signature scheme (ML-DSA, FIPS 204)** and benchmarked it against a classical signature (Ed25519).

The API is a tiny bank with two accounts and a transfer endpoint, so a successful attack has a visible effect: money moves.

## What it does

Every protected request carries five headers:

| Header | Purpose |
| --- | --- |
| `X-Client-Id` | Who is calling. The server looks up that client's key and algorithm. |
| `X-Signature-Alg` | `hmac-sha256`, `ed25519` or `ml-dsa-65`. Must match the client's registered algorithm. |
| `X-Timestamp` | When the request was signed. Requests older than 60 seconds are rejected. |
| `X-Nonce` | A random value that can only be used once. |
| `X-Signature` | The signature, base64-encoded. |

The client signs a **canonical string** made from every part of the request an attacker might change:

```
METHOD \n PATH \n CLIENT_ID \n ALG \n TIMESTAMP \n NONCE \n SHA256(BODY)
```

The server rebuilds the same string from the request it received and checks the signature in this order:

1. All five headers present → otherwise `missing_headers`
2. Client known, algorithm matches the one registered for it → otherwise `unknown_client` / `wrong_algorithm`
3. Timestamp no more than 60 s old and not in the future → otherwise `expired` / `future_timestamp`
4. Signature valid for this exact method, path, body, timestamp and nonce → otherwise `bad_signature`
5. Nonce not seen before → otherwise `replay`

The nonce is checked **after** the signature, so an attacker can't use forged requests to fill up the nonce store or burn a real client's nonce.

Three demo clients use the three algorithms:

| Client | Algorithm | Type |
| --- | --- | --- |
| `hmac-client` | HMAC-SHA256 | Symmetric: client and server share one secret |
| `ed25519-client` | Ed25519 | Classical public-key signature |
| `mldsa-client` | ML-DSA-65 | Post-quantum public-key signature (NIST FIPS 204) |

There is also an unprotected `/insecure/transfer` endpoint as a baseline.

## Project layout

```
quantumsign/
  signing.py     canonical string, sign and verify for all three algorithms
  keys.py        key generation and loading
  server.py      Flask API, signature check, nonce store, /metrics
  client.py      command-line client that signs its requests
attacks/
  run_attacks.py         replay, tampering, forgery and downgrade attacks
  mitm_tamper_addon.py   the same attacks live through mitmproxy
benchmarks/
  benchmark.py   key size, signature size and speed: Ed25519 vs ML-DSA
tests/
  test_api.py    30 pytest tests
results/         attack and benchmark reports from my run
```

## Run it

Needs Python 3.11+ and `cryptography` 50 or newer (ML-DSA support is built into the library, so no liboqs is needed).

```bash
pip install -r requirements.txt
python -m quantumsign.keys                 # create demo keys in keys/
python -m quantumsign.server               # API on http://127.0.0.1:5000

# in a second terminal
python -m quantumsign.client --client mldsa-client transfer alice bob 25
python -m quantumsign.client --client ed25519-client balances

python attacks/run_attacks.py              # all attacks, report in results/
python benchmarks/benchmark.py             # benchmark, report in results/
pytest -q                                  # tests
```

To watch the attacks happen on the wire, put mitmproxy in front of the API (instructions at the top of `attacks/mitm_tamper_addon.py`).

## Attack results

The attacker sits between client and server. They can copy, change and resend real signed requests but do not have the client's key. Full report: [`results/attack_results.md`](results/attack_results.md).

**Without protection** (`/insecure/transfer`), both attacks work: replaying a £10 transfer moves another £10, and changing the amount to 900 moves £900.

**With signed requests**, every attack was blocked, with the same result for HMAC, Ed25519 and ML-DSA-65:

| Attack | Blocked by | Result |
| --- | --- | --- |
| Replay the captured request immediately | Nonce | 401 `replay` |
| Replay an old request after the window | Timestamp | 401 `expired` |
| Change the amount from 10 to 900 | Signature (body hash) | 401 `bad_signature` |
| Reuse a `GET /api/balances` signature on `POST /api/transfer` | Signature (method and path) | 401 `bad_signature` |
| Put a fresh timestamp on an expired request | Signature (timestamp is signed) | 401 `bad_signature` |
| Sign with the attacker's own key | Signature | 401 `bad_signature` |
| Remove all signature headers | Header check | 401 `missing_headers` |
| Set the algorithm to `none` | Algorithm fixed per client | 401 `wrong_algorithm` |

No money moved in any blocked attack. Each rejection is logged and counted at `/metrics` in Prometheus format, so it could feed a Grafana alert.

## Benchmark: Ed25519 vs ML-DSA

Measured with `cryptography` 50.0.1 on Linux x86_64, Python 3.13, medians over 2,000 runs. Full report: [`results/benchmark.md`](results/benchmark.md).

**Sizes (bytes)**

| Scheme | Public key | Signature | Signature as base64 header |
| --- | --- | --- | --- |
| Ed25519 | 32 | 64 | 88 |
| ML-DSA-44 | 1,312 | 2,420 | 3,228 |
| ML-DSA-65 | 1,952 | 3,309 | 4,412 |
| ML-DSA-87 | 2,592 | 4,627 | 6,172 |

**Speed (microseconds)**

| Scheme | Key generation | Sign | Verify |
| --- | --- | --- | --- |
| Ed25519 | 29.8 | 30.3 | 99.5 |
| ML-DSA-44 | 100.0 | 426.2 | 110.6 |
| ML-DSA-65 | 219.5 | 730.7 | 163.0 |
| ML-DSA-87 | 249.0 | 825.2 | 266.4 |

**Full signed request through the API (localhost)**

| Algorithm | Median | 95th percentile | Signature headers |
| --- | --- | --- | --- |
| HMAC-SHA256 | 1.36 ms | 1.79 ms | 183 bytes |
| Ed25519 | 1.58 ms | 1.89 ms | 226 bytes |
| ML-DSA-65 | 2.52 ms | 4.03 ms | 4,550 bytes |

## What I found

- **A signature on its own does not stop replay.** A replayed request has a perfectly valid signature. The timestamp limits replay to a 60-second window, and the nonce closes that window. The server only needs to remember nonces for as long as the timestamp check would still pass them, so the store stays small.
- **Everything the server acts on has to be signed.** The attacks that changed the timestamp, or reused a signature on a different endpoint, only fail because the timestamp, method and path are inside the canonical string.
- **Don't let the request choose the algorithm.** The algorithm is fixed per client on the server, which blocks downgrade tricks like `alg: none`.
- **ML-DSA's cost is size more than speed.** An ML-DSA-65 signature is 52 times larger than Ed25519 and its public key 61 times larger. Signing is about 24 times slower, but verifying, which is the work the server does on every request, is only about 1.6 times slower. End to end, ML-DSA-65 added under 1 ms per request.
- **The size matters for APIs and mobile apps.** ML-DSA-65 adds about 4.4 KB of headers to every request, and ML-DSA-87 about 6.2 KB. That fits under the common 8 KB header limit, but some proxies, load balancers and CDNs set lower limits, and on mobile networks it is extra data on every call.

## Limitations and next steps

- The nonce store is in memory, so it only works for one server process. In production it would go in Redis with a TTL, shared by every instance.
- Demo keys are stored unencrypted in `keys/`. Real private keys belong in a secrets manager, HSM or the device's secure hardware.
- Request signing works alongside TLS, not instead of it. It protects requests even where TLS is ended at a proxy or intercepted.
- If an attacker extracts the private key from the client app, they can sign valid requests. Proving the request came from a genuine, untampered app is a separate problem, and the one app attestation tools aim to solve.
- Next: a **hybrid signature** (Ed25519 + ML-DSA, both must verify), which is how many teams plan to move to post-quantum cryptography while it is still new, and putting the signature in the body instead of headers to avoid header-size limits.
