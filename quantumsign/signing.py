"""Request signing shared by the client and the server.

Every protected request carries these headers:

    X-Client-Id      who is calling (decides which key the server checks)
    X-Signature-Alg  hmac-sha256 | ed25519 | ml-dsa-65
    X-Timestamp      Unix time in seconds when the request was signed
    X-Nonce          random value, used once
    X-Signature      base64 signature over the canonical string below

The signature covers a "canonical string" built from every part of the
request an attacker might want to change:

    METHOD \n PATH \n CLIENT_ID \n ALG \n TIMESTAMP \n NONCE \n SHA256(BODY)

So changing the body, the path, the timestamp or the nonce breaks the
signature. The timestamp stops old requests being replayed later, and the
nonce stops a captured request being replayed straight away.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

ALG_HMAC = "hmac-sha256"
ALG_ED25519 = "ed25519"
ALG_MLDSA = "ml-dsa-65"
ALGORITHMS = (ALG_HMAC, ALG_ED25519, ALG_MLDSA)

SIGNATURE_HEADERS = (
    "X-Client-Id",
    "X-Signature-Alg",
    "X-Timestamp",
    "X-Nonce",
    "X-Signature",
)


def canonical_string(method: str, path: str, client_id: str, alg: str,
                     timestamp: str, nonce: str, body: bytes) -> bytes:
    """Build the exact bytes that get signed. Client and server must agree."""
    body_hash = hashlib.sha256(body or b"").hexdigest()
    parts = [method.upper(), path, client_id, alg, timestamp, nonce, body_hash]
    return "\n".join(parts).encode("utf-8")


def sign(alg: str, key, message: bytes) -> bytes:
    """Sign a message. `key` is bytes for HMAC, a private key object otherwise."""
    if alg == ALG_HMAC:
        return hmac.new(key, message, hashlib.sha256).digest()
    if alg == ALG_ED25519:
        return key.sign(message)
    if alg == ALG_MLDSA:
        return key.sign(message)
    raise ValueError(f"unsupported algorithm: {alg}")


def verify(alg: str, key, message: bytes, signature: bytes) -> bool:
    """Return True only if the signature is valid. Never raises on a bad signature."""
    try:
        if alg == ALG_HMAC:
            expected = hmac.new(key, message, hashlib.sha256).digest()
            # compare_digest takes the same time whether the first byte or the
            # last byte is wrong, so an attacker can't guess it byte by byte.
            return hmac.compare_digest(expected, signature)
        if alg == ALG_ED25519:
            if not isinstance(key, ed25519.Ed25519PublicKey):
                return False
            key.verify(signature, message)
            return True
        if alg == ALG_MLDSA:
            if not isinstance(key, mldsa.MLDSA65PublicKey):
                return False
            key.verify(signature, message)
            return True
    except Exception:
        return False
    return False


def signed_headers(method: str, path: str, body: bytes, client_id: str,
                   alg: str, key, timestamp: int | None = None,
                   nonce: str | None = None) -> dict[str, str]:
    """Produce the signature headers for a request (used by the client)."""
    ts = str(int(time.time()) if timestamp is None else timestamp)
    nonce = nonce or secrets.token_hex(16)
    message = canonical_string(method, path, client_id, alg, ts, nonce, body)
    signature = sign(alg, key, message)
    return {
        "X-Client-Id": client_id,
        "X-Signature-Alg": alg,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": base64.b64encode(signature).decode("ascii"),
    }
