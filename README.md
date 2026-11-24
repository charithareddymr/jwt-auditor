# jwt-auditor

[![CI](https://github.com/charithareddymr/jwt-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/charithareddymr/jwt-auditor/actions/workflows/ci.yml)

A small tool that checks a JWT-protected API for the validation flaws that keep
showing up in real systems: unsigned tokens, weak secrets, algorithm confusion,
missing expiry and unverified signatures. It ships with a deliberately vulnerable
demo API so the whole thing runs locally, and a secure version of that API that
every check passes, proving the tool doesn't cry wolf.

```
Vulnerable build:  3 vulnerabilities found across 5 checks
Secure build:      0 vulnerabilities found across 5 checks
```

> **Authorized testing only.** Use this against systems you own or have explicit
> written permission to test. The CLI refuses to run without `--authorized`, and
> the bundled demo API binds to `127.0.0.1` so it is never exposed to the network.
> It is a practice target, in the spirit of OWASP Juice Shop or WebGoat.

---

## Why JWTs fail

A JSON Web Token carries its own `alg` header saying how it was signed. The
original sin of many JWT libraries is trusting that header, so the token gets to
choose how it's checked. From that one mistake grows a family of attacks. This
tool automates the five most common, each from the attacker's side (does the
server actually accept the manipulation?) and reports the fix.

| # | Flaw | What the tool does | Fix it reports |
|---|---|---|---|
| 1 | **`alg: none`** | Sends an unsigned token claiming `role: admin` | Pin the algorithm server-side; never honour `none` |
| 2 | **Weak HMAC secret** | Brute-forces the real token against a common-secret list, then forges an admin token | Long random secret from a secret manager, or move to RS256/ES256 |
| 3 | **RS/HS algorithm confusion** | Signs an HS256 token using the server's own RS256 **public** key | Pin to the asymmetric algorithm; reject HMAC on verify |
| 4 | **No / unenforced expiry** | Flags a missing `exp`, or forges an already-expired token | Always set and verify a short `exp` |
| 5 | **Signature not verified** | Tampers the payload, keeps the original signature | Verify the signature before trusting any claim |

The algorithm-confusion check is the interesting one. A server that normally
issues RS256 tokens, but trusts the header, will verify an incoming HS256 token
using its RSA public key as the HMAC secret. The public key isn't secret, so
anyone can forge tokens. PyJWT refuses to even construct that token (a good
safety default), so the tool builds it by hand.

---

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/charithareddymr/jwt-auditor.git
cd jwt-auditor
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Start the demo target in one terminal:

```bash
python -m demo_api.app              # vulnerable build
# JWT_SECURE=1 python -m demo_api.app   # secure build
```

Audit it from another:

```bash
python -m auditor.cli \
    --url http://127.0.0.1:5000 \
    --login /login --username alice --password password123 \
    --protected /me --admin /admin \
    --jwks http://127.0.0.1:5000/.well-known/jwks.json \
    --authorized
```

The tool logs in as the low-privilege user `alice`, then checks whether any
manipulation lets her reach the admin-only `/admin` endpoint. It exits non-zero
when it finds a vulnerability, so it drops straight into a CI gate.

---

## How a check proves a finding

A check never needs a server-side secret. It works only from a token the server
already issued to the tester, plus the server's public JWKS when one is
published. A finding is only reported as **vulnerable** when the manipulated
token actually reaches the elevated endpoint, not merely when it's accepted.
That keeps false positives down: the secure build returns zero.

```
POST /login  (as alice, role=user)   ->  legitimate token
forge/alter the token per each flaw  ->  GET /admin
HTTP 200 + admin data                ->  VULNERABLE
HTTP 401/403                          ->  safe
```

---

## Tests

```bash
python -m pytest -v    # 8 tests
```

The tests start the demo API in each mode on a local port and run the full
auditor, asserting three vulnerabilities on the vulnerable build and none on the
secure one. They also confirm the `alg: none` forgery truly reaches `/admin`,
that the CLI refuses to run without `--authorized`, and that the exit code
signals findings. CI runs them plus a Bandit scan of the tool on every push.

---

## Limitations

- **Black-box expiry testing.** Against an RS256 service the tool can confirm an
  `exp` claim exists but can't forge an expired token without the private key, so
  it reports that honestly rather than guessing.
- **Not a full JWT fuzzer.** It covers five high-value flaws, not the entire
  space (e.g. `jku`/`kid` injection, JWE, nested tokens). The code is structured
  so each check is one small function; adding more is straightforward.
- **The secret list is short.** Real auditing uses large wordlists; the bundled
  list is just long enough to demonstrate the weak-secret path.

## Project layout

```
auditor/
  checks.py    the five checks, each independent and transport-agnostic
  target.py    HTTP interactions with the API under test
  report.py    text / JSON output, sorted by severity
  cli.py       command-line interface with the authorization gate
demo_api/
  app.py       the practice target: create_app(secure=False|True)
  keys.py      throwaway RSA keys + JWKS
tests/         end-to-end and unit tests
```

## License

MIT
