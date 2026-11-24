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
import datetime
import os

import jwt
from flask import Flask, jsonify, request

from demo_api import keys

# A weak, guessable secret: one of the classic mistakes. The secure build signs
# with an RSA private key instead, so there is no shared secret at all.
WEAK_SECRET = "secret"
ISSUER = "https://demo-api.local"
AUDIENCE = "demo-api"

USERS = {
    "alice": {"password": "password123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}


def issue_token(username, role, secure):
    claims = {"sub": username, "role": role, "iss": ISSUER, "aud": AUDIENCE}
    if secure:
        # Fix: sign with RS256 using a private key, set an expiry, pin the kid.
        now = datetime.datetime.now(datetime.timezone.utc)
        claims["iat"] = now
        claims["exp"] = now + datetime.timedelta(minutes=15)
        return jwt.encode(claims, keys.rsa_private_pem(), algorithm="RS256",
                          headers={"kid": keys.SECURE_KID})
    # Vulnerable: HS256 with a weak secret and no expiry.
    return jwt.encode(claims, WEAK_SECRET, algorithm="HS256")


def verify_token(token, secure):
    """Return the token's claims, or raise jwt.InvalidTokenError."""
    if secure:
        # Fix: pin the algorithm to RS256 (blocks 'none' and HS/RS confusion),
        # verify with the PUBLIC key only, and require iss/aud/exp.
        return jwt.decode(
            token, keys.rsa_public_pem(), algorithms=["RS256"],
            issuer=ISSUER, audience=AUDIENCE,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )

    # Vulnerable verification, each line a real-world mistake:
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "HS256")
    if alg == "none":
        return jwt.decode(token, options={"verify_signature": False})  # accepts unsigned
    # Trusts the token's own algorithm choice, and never checks expiry.
    return jwt.decode(
        token, WEAK_SECRET, algorithms=[alg],
        options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
    )


def create_app(secure=False):
    app = Flask(__name__)
    app.config["SECURE"] = secure

    def _bearer():
        header = request.headers.get("Authorization", "")
        return header[7:] if header.lower().startswith("bearer ") else None

    def _claims_or_401():
        token = _bearer()
        if not token:
            return None, (jsonify(error="missing token"), 401)
        try:
            return verify_token(token, app.config["SECURE"]), None
        except jwt.InvalidTokenError as exc:
            return None, (jsonify(error=f"invalid token: {exc}"), 401)

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        user = USERS.get(body.get("username"))
        if not user or user["password"] != body.get("password"):
            return jsonify(error="invalid credentials"), 401
        return jsonify(token=issue_token(body["username"], user["role"], app.config["SECURE"]))

    @app.get("/me")
    def me():
        claims, err = _claims_or_401()
        if err:
            return err
        return jsonify(user=claims.get("sub"), role=claims.get("role"))

    @app.get("/admin")
    def admin():
        claims, err = _claims_or_401()
        if err:
            return err
        if claims.get("role") != "admin":
            return jsonify(error="forbidden"), 403
        return jsonify(secret="flag{admin-only-data}", user=claims.get("sub"))

    @app.get("/.well-known/jwks.json")
    def jwks():
        # Publishing the RS256 public key is what makes algorithm-confusion testable,
        # and why pinning the algorithm server-side matters.
        return jsonify(keys.public_jwks())

    return app


if __name__ == "__main__":
    secure = os.environ.get("JWT_SECURE") == "1"
    print(f"Demo API in {'SECURE' if secure else 'VULNERABLE'} mode on "
          "http://127.0.0.1:5000  (local practice target only)")
    create_app(secure).run(host="127.0.0.1", port=5000)
