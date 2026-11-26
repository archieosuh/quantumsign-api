# Benchmark results

Run at 2026-11-26 06:53:51 GMT on Darwin arm64, Python 3.12.6, cryptography 50.0.2 (OpenSSL backend). Timings are medians over 2000 runs.

## Sizes (bytes)

| Scheme | Public key | Private key* | Signature | Signature as base64 header | Signature vs Ed25519 |
| --- | --- | --- | --- | --- | --- |
| Ed25519 (classical) | 32 | 32 | 64 | 88 | 1x |
| ML-DSA-44 (post-quantum, NIST level 2) | 1312 | 32 | 2420 | 3228 | 38x |
| ML-DSA-65 (post-quantum, NIST level 3) | 1952 | 32 | 3309 | 4412 | 52x |
| ML-DSA-87 (post-quantum, NIST level 5) | 2592 | 32 | 4627 | 6172 | 72x |
| HMAC-SHA256 (shared secret, reference) | - | 32 | 32 | 44 | - |

\* Private keys are stored as 32-byte seeds. An ML-DSA private key expanded from its seed is much larger (2560 / 4032 / 4896 bytes for ML-DSA-44/65/87).

## Speed (microseconds, lower is better)

| Scheme | Key generation | Sign | Verify |
| --- | --- | --- | --- |
| Ed25519 (classical) | 27.3 | 28.2 | 81.3 |
| ML-DSA-44 (post-quantum, NIST level 2) | 66.9 | 274.3 | 70.6 |
| ML-DSA-65 (post-quantum, NIST level 3) | 122.2 | 470.2 | 108.8 |
| ML-DSA-87 (post-quantum, NIST level 5) | 169.3 | 555.3 | 171.7 |
| HMAC-SHA256 (shared secret, reference) | 1.0 | 1.2 | 1.3 |

## End-to-end signed request through the API (localhost)

| Algorithm | Median (ms) | 95th percentile (ms) | Signature headers (bytes) |
| --- | --- | --- | --- |
| hmac-sha256 | 1.47 | 2.78 | 183 |
| ed25519 | 2.08 | 5.98 | 226 |
| ml-dsa-65 | 2.49 | 4.39 | 4550 |
