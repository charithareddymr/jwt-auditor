"""A deliberately vulnerable (and, in secure mode, fixed) demo API for learning
how JWT validation goes wrong.

This exists ONLY as a local practice target, like OWASP Juice Shop or WebGoat.
It binds to 127.0.0.1 so it is not reachable from the network. Do not deploy it.

Run the vulnerable version (default):
    python -m demo_api.app
Run the fixed version:
    JWT_SECURE=1 python -m demo_api.app

Endpoints:
    POST /login         -> returns a token for {"username": "...", "password": "..."}
    GET  /me            -> returns the caller's identity from their token
    GET  /admin         -> requires an admin token
    GET  /.well-known/jwks.json  -> the public key (secure mode advertises RS256)
"""
import os

import jwt
from flask import Flask, jsonify, request

from demo_api import keys

SECURE = os.environ.get("JWT_SECURE") == "1"

# A weak, guessable secret: one of the classic mistakes. The secure build loads a
# strong secret from the environment instead (see secure_secret()).
WEAK_SECRET = "secret"
ISSUER = "https://demo-api.local"
AUDIENCE = "demo-api"

USERS = {
    "alice": {"password": "password123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}

app = Flask(__name__)


def secure_secret():
    # In secure mode the HMAC secret is long, random and comes from the environment,
    # never hard-coded. We generate one per process if the operator didn't set it.
    return os.environ.get("JWT_SECRET") or keys.ephemeral_hmac_secret()


def issue_token(username, role):
    claims = {"sub": username, "role": role, "iss": ISSUER, "aud": AUDIENCE}
    if SECURE:
        # Fix: sign with RS256 using a private key, set an expiry, and pin the kid.
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        claims["iat"] = now
        claims["exp"] = now + datetime.timedelta(minutes=15)
        headers = {"kid": keys.SECURE_KID}
        return jwt.encode(claims, keys.rsa_private_pem(), algorithm="RS256", headers=headers)
    # Vulnerable: HS256 with a weak secret and no expiry.
    return jwt.encode(claims, WEAK_SECRET, algorithm="HS256")


def verify_token(token):
    """Return the token's claims, or raise jwt.InvalidTokenError."""
    if SECURE:
        # Fix: pin the algorithm to RS256 (blocks 'none' and HS/RS confusion),
        # verify with the PUBLIC key only, and require iss/aud/exp.
        return jwt.decode(
            token,
            keys.rsa_public_pem(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )

    # Vulnerable verification, each line a real-world mistake:
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "HS256")
    if alg == "none":
        # Accepts unsigned tokens.
        return jwt.decode(token, options={"verify_signature": False})
    # Trusts the token's own algorithm choice, enabling alg-confusion, and never
    # checks expiry.
    return jwt.decode(
        token, WEAK_SECRET, algorithms=[alg],
        options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
    )


@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    user = USERS.get(body.get("username"))
    if not user or user["password"] != body.get("password"):
        return jsonify(error="invalid credentials"), 401
    return jsonify(token=issue_token(body["username"], user["role"]))


@app.get("/me")
def me():
    token = _bearer()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        claims = verify_token(token)
    except jwt.InvalidTokenError as exc:
        return jsonify(error=f"invalid token: {exc}"), 401
    return jsonify(user=claims.get("sub"), role=claims.get("role"))


@app.get("/admin")
def admin():
    token = _bearer()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        claims = verify_token(token)
    except jwt.InvalidTokenError as exc:
        return jsonify(error=f"invalid token: {exc}"), 401
    if claims.get("role") != "admin":
        return jsonify(error="forbidden"), 403
    return jsonify(secret="flag{admin-only-data}", user=claims.get("sub"))


@app.get("/.well-known/jwks.json")
def jwks():
    # Secure mode publishes its RS256 public key, as a real OIDC provider would.
    # This is exactly what makes algorithm-confusion testable, and why pinning
    # the algorithm server-side matters.
    return jsonify(keys.public_jwks())


def _bearer():
    header = request.headers.get("Authorization", "")
    return header[7:] if header.lower().startswith("bearer ") else None


if __name__ == "__main__":
    mode = "SECURE" if SECURE else "VULNERABLE"
    print(f"Demo API in {mode} mode on http://127.0.0.1:5000  (local practice target only)")
    app.run(host="127.0.0.1", port=5000)
