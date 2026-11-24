"""Describes the API under test and performs the HTTP interactions the checks need.

The checks stay transport-agnostic; everything that touches the network lives here.
"""
import requests

from auditor.checks import decode_parts


class Target:
    def __init__(self, base_url, token, protected_path, admin_path=None,
                 jwks_url=None, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.legit_token = token
        self.protected_path = protected_path
        self.admin_path = admin_path or protected_path
        self.jwks_url = jwks_url
        self.timeout = timeout
        _, self.sample_payload = decode_parts(token)

    # -- what the checks call ------------------------------------------------ #
    def token_accepted(self, token):
        """True if the protected endpoint accepts this token (HTTP 2xx)."""
        return self._get(self.protected_path, token).ok

    def reaches_admin(self, token):
        """True if this token is accepted at the admin-only endpoint (HTTP 2xx)."""
        return self._get(self.admin_path, token).ok

    def public_key_pem(self):
        """Fetch the RSA public key from the JWKS endpoint, as PEM, or None."""
        if not self.jwks_url:
            return None
        try:
            jwks = requests.get(self.jwks_url, timeout=self.timeout).json()
        except Exception:
            return None
        for key in jwks.get("keys", []):
            if key.get("kty") == "RSA":
                return _jwk_to_pem(key)
        return None

    # -- helpers ------------------------------------------------------------- #
    def _get(self, path, token):
        return requests.get(self.base_url + path, timeout=self.timeout,
                            headers={"Authorization": f"Bearer {token}"})


def login(base_url, login_path, username, password, timeout=10):
    """Log in and return the raw token string. Raises on failure."""
    resp = requests.post(base_url.rstrip("/") + login_path,
                         json={"username": username, "password": password}, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    token = data.get("token") or data.get("access_token") or data.get("jwt")
    if not token:
        raise ValueError(f"No token field in login response: {list(data)}")
    return token


def _jwk_to_pem(jwk):
    import base64
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives import serialization

    def num(v):
        return int.from_bytes(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)), "big")

    pub = RSAPublicNumbers(num(jwk["e"]), num(jwk["n"])).public_key()
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)
