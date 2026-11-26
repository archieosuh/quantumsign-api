# Attack results

Run at 2026-11-26 06:53:44 GMT. `money_moved` is the change in Bob's balance caused by that request.

## Baseline: /insecure/transfer (no protection)

| Attack | HTTP | Reason | Money moved | Outcome | As expected |
| --- | --- | --- | --- | --- | --- |
| Legitimate request (control) | 200 | - | 10 | ACCEPTED | yes |
| Replay: resend captured request immediately | 200 | - | 10 | ACCEPTED | yes |
| Tamper: change amount 10 -> 900 | 200 | - | 900 | ACCEPTED | yes |

## Protected: /api/transfer with hmac-sha256

| Attack | HTTP | Reason | Money moved | Outcome | As expected |
| --- | --- | --- | --- | --- | --- |
| Legitimate signed request (control) | 200 | - | 10 | ACCEPTED | yes |
| Replay: resend captured request immediately | 401 | replay | 0 | BLOCKED | yes |
| Delayed replay: request signed 120s ago | 401 | expired | 0 | BLOCKED | yes |
| Tamper: change amount 10 -> 900 | 401 | bad_signature | 0 | BLOCKED | yes |
| Tamper: reuse GET /api/balances signature on POST /api/transfer | 401 | bad_signature | 0 | BLOCKED | yes |
| Tamper: refresh the timestamp on an expired request | 401 | bad_signature | 0 | BLOCKED | yes |
| Forge: sign with attacker's own key | 401 | bad_signature | 0 | BLOCKED | yes |
| Strip: remove all signature headers | 401 | missing_headers | 0 | BLOCKED | yes |
| Downgrade: set X-Signature-Alg to 'none' | 401 | wrong_algorithm | 0 | BLOCKED | yes |

## Protected: /api/transfer with ed25519

| Attack | HTTP | Reason | Money moved | Outcome | As expected |
| --- | --- | --- | --- | --- | --- |
| Legitimate signed request (control) | 200 | - | 10 | ACCEPTED | yes |
| Replay: resend captured request immediately | 401 | replay | 0 | BLOCKED | yes |
| Delayed replay: request signed 120s ago | 401 | expired | 0 | BLOCKED | yes |
| Tamper: change amount 10 -> 900 | 401 | bad_signature | 0 | BLOCKED | yes |
| Tamper: reuse GET /api/balances signature on POST /api/transfer | 401 | bad_signature | 0 | BLOCKED | yes |
| Tamper: refresh the timestamp on an expired request | 401 | bad_signature | 0 | BLOCKED | yes |
| Forge: sign with attacker's own key | 401 | bad_signature | 0 | BLOCKED | yes |
| Strip: remove all signature headers | 401 | missing_headers | 0 | BLOCKED | yes |
| Downgrade: set X-Signature-Alg to 'none' | 401 | wrong_algorithm | 0 | BLOCKED | yes |

## Protected: /api/transfer with ml-dsa-65

| Attack | HTTP | Reason | Money moved | Outcome | As expected |
| --- | --- | --- | --- | --- | --- |
| Legitimate signed request (control) | 200 | - | 10 | ACCEPTED | yes |
| Replay: resend captured request immediately | 401 | replay | 0 | BLOCKED | yes |
| Delayed replay: request signed 120s ago | 401 | expired | 0 | BLOCKED | yes |
| Tamper: change amount 10 -> 900 | 401 | bad_signature | 0 | BLOCKED | yes |
| Tamper: reuse GET /api/balances signature on POST /api/transfer | 401 | bad_signature | 0 | BLOCKED | yes |
| Tamper: refresh the timestamp on an expired request | 401 | bad_signature | 0 | BLOCKED | yes |
| Forge: sign with attacker's own key | 401 | bad_signature | 0 | BLOCKED | yes |
| Strip: remove all signature headers | 401 | missing_headers | 0 | BLOCKED | yes |
| Downgrade: set X-Signature-Alg to 'none' | 401 | wrong_algorithm | 0 | BLOCKED | yes |
