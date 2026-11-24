"""Tests for the JWT auditor.

Each test starts the demo API (in vulnerable or secure mode) on a local port in
a background thread, then runs the full auditor against it, exactly as a user
would. No real network or external service is involved, so this runs in CI.

Run from the project root:
    python -m pytest -v
"""
import threading
import warnings

import pytest
import requests
from werkzeug.serving import make_server

from auditor.checks import _hs256_with_key, decode_parts
from auditor.cli import run_audit
from auditor.target import Target, login
from demo_api.app import create_app

# PyJWT warns when it signs/verifies with the demo's short HMAC secret; that weak
# secret is the point of the vulnerable build, so silence the noise in tests.
warnings.filterwarnings("ignore", message=".*HMAC key.*")


class _Server:
    def __init__(self, secure):
        self.httpd = make_server("127.0.0.1", 0, create_app(secure))
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *exc):
        self.httpd.shutdown()


def audit(base_url):
    token = login(base_url, "/login", "alice", "password123")
    target = Target(base_url, token, "/me", "/admin", base_url + "/.well-known/jwks.json")
    return {f.check_id: f for f in run_audit(target)}


# --------------------------------------------------------------- end to end
def test_vulnerable_api_is_flagged():
    with _Server(secure=False) as url:
        findings = audit(url)
    vulns = {cid for cid, f in findings.items() if f.status == "vulnerable"}
    assert vulns == {"alg-none", "weak-secret", "no-expiry"}
    assert findings["alg-none"].severity == "critical"
    assert findings["weak-secret"].evidence["recovered_secret"] == "secret"


def test_secure_api_is_clean():
    with _Server(secure=True) as url:
        findings = audit(url)
    assert all(f.status != "vulnerable" for f in findings.values())


def test_alg_none_actually_reaches_admin_on_vulnerable_api():
    with _Server(secure=False) as url:
        token = login(url, "/login", "alice", "password123")
        _, payload = decode_parts(token)
        assert payload["role"] == "user"  # we logged in as a normal user
        import base64, json
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps({**payload, "role": "admin"}).encode()).rstrip(b"=").decode()
        forged = f"{header}.{body}."
        r = requests.get(url + "/admin", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 200 and "flag" in r.json()["secret"]


def test_secure_api_rejects_alg_none():
    with _Server(secure=True) as url:
        forged = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9."
        r = requests.get(url + "/admin", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401


# --------------------------------------------------------------- unit level
def test_cli_refuses_without_authorization(capsys):
    from auditor.cli import main
    code = main(["--url", "http://127.0.0.1:1", "--login", "/login",
                 "--username", "a", "--password", "b", "--protected", "/me"])
    assert code == 2
    assert "Refusing to run" in capsys.readouterr().err


def test_hs256_with_key_roundtrips():
    import hmac, hashlib, base64, json
    token = _hs256_with_key({"role": "admin"}, b"any-bytes")
    h, p, s = token.split(".")
    expected = base64.urlsafe_b64encode(
        hmac.new(b"any-bytes", f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert s == expected
    assert json.loads(base64.urlsafe_b64decode(p + "=="))["role"] == "admin"


def test_exit_code_signals_vulnerabilities():
    from auditor.cli import main
    with _Server(secure=False) as url:
        code = main(["--url", url, "--login", "/login", "--username", "alice",
                     "--password", "password123", "--protected", "/me", "--admin", "/admin",
                     "--jwks", url + "/.well-known/jwks.json", "--authorized"])
    assert code == 1  # vulnerabilities found -> non-zero, useful in CI


def test_exit_code_clean_on_secure():
    from auditor.cli import main
    with _Server(secure=True) as url:
        code = main(["--url", url, "--login", "/login", "--username", "alice",
                     "--password", "password123", "--protected", "/me", "--admin", "/admin",
                     "--jwks", url + "/.well-known/jwks.json", "--authorized"])
    assert code == 0
