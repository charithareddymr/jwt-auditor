"""Key material for the demo API.

Keys are generated once and cached on disk under demo_api/.keys/ so the
vulnerable and secure servers, and the tests, all agree on the same key.
These are throwaway demo keys for a local practice target. Never reuse them.
"""
import base64
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = Path(__file__).resolve().parent / ".keys"
PRIV = KEY_DIR / "rsa_private.pem"
PUB = KEY_DIR / "rsa_public.pem"
SECURE_KID = "demo-rsa-1"


def _ensure_rsa():
    if PRIV.exists() and PUB.exists():
        return
    KEY_DIR.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIV.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    PUB.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def rsa_private_pem():
    _ensure_rsa()
    return PRIV.read_bytes()


def rsa_public_pem():
    _ensure_rsa()
    return PUB.read_bytes()


def ephemeral_hmac_secret():
    return secrets.token_urlsafe(48)


def _b64url_uint(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_jwks():
    """Publish the RSA public key in JWKS form, as a real OIDC provider does."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pub = load_pem_public_key(rsa_public_pem())
    numbers = pub.public_numbers()
    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": SECURE_KID,
        "n": _b64url_uint(numbers.n), "e": _b64url_uint(numbers.e),
    }]}
