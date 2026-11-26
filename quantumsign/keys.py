"""Key generation and loading.

Run `python -m quantumsign.keys` once to create the keys/ folder.
Private keys stay with the client. The server only needs the public keys
(and the HMAC secret, because HMAC is symmetric: both sides share one key).
"""

from __future__ import annotations

import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from .signing import ALG_ED25519, ALG_HMAC, ALG_MLDSA

KEY_DIR = Path(__file__).resolve().parent.parent / "keys"

# One demo client per algorithm.
CLIENTS = {
    "hmac-client": ALG_HMAC,
    "ed25519-client": ALG_ED25519,
    "mldsa-client": ALG_MLDSA,
}


def generate_keys(key_dir: Path = KEY_DIR) -> None:
    key_dir.mkdir(parents=True, exist_ok=True)

    (key_dir / "hmac-client.secret").write_bytes(secrets.token_bytes(32))

    for name, private in (
        ("ed25519-client", ed25519.Ed25519PrivateKey.generate()),
        ("mldsa-client", mldsa.MLDSA65PrivateKey.generate()),
    ):
        (key_dir / f"{name}.private.pem").write_bytes(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        (key_dir / f"{name}.public.pem").write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"Keys written to {key_dir}")


def ensure_keys(key_dir: Path = KEY_DIR) -> None:
    if not (key_dir / "hmac-client.secret").exists():
        generate_keys(key_dir)


def load_client_key(client_id: str, key_dir: Path = KEY_DIR):
    """The key a client signs with: HMAC secret or private key."""
    if CLIENTS[client_id] == ALG_HMAC:
        return (key_dir / f"{client_id}.secret").read_bytes()
    pem = (key_dir / f"{client_id}.private.pem").read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def load_server_registry(key_dir: Path = KEY_DIR) -> dict[str, dict]:
    """What the server knows about each client: its algorithm and verify key.

    The algorithm is fixed per client here, not taken from the request,
    so an attacker can't ask the server to check with a weaker algorithm.
    """
    registry = {}
    for client_id, alg in CLIENTS.items():
        if alg == ALG_HMAC:
            key = (key_dir / f"{client_id}.secret").read_bytes()
        else:
            pem = (key_dir / f"{client_id}.public.pem").read_bytes()
            key = serialization.load_pem_public_key(pem)
        registry[client_id] = {"alg": alg, "key": key}
    return registry


if __name__ == "__main__":
    generate_keys()
