"""Command-line entry point for the JWT auditor.

Only test systems you own or have explicit written permission to test. The tool
requires you to confirm that each run, with --authorized, and refuses otherwise.

Example (against the bundled demo API running locally):
    python -m auditor.cli \\
        --url http://127.0.0.1:5000 \\
        --login /login --username alice --password password123 \\
        --protected /me --admin /admin \\
        --jwks http://127.0.0.1:5000/.well-known/jwks.json \\
        --authorized
"""
import argparse
import sys

from auditor import report
from auditor.checks import ALL_CHECKS, Finding
from auditor.target import Target, login


def run_audit(target):
    findings = []
    for check in ALL_CHECKS:
        try:
            findings.append(check(target))
        except Exception as exc:  # a broken check shouldn't abort the whole run
            findings.append(Finding(check.__name__, check.__name__, "info", "error",
                                    f"Check raised an error: {exc}"))
    return findings


def main(argv=None):
    p = argparse.ArgumentParser(description="Audit a JWT-protected API for common flaws.")
    p.add_argument("--url", required=True, help="Base URL of the target API")
    p.add_argument("--login", required=True, help="Login path, e.g. /login")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--protected", required=True, help="A path that needs a valid token")
    p.add_argument("--admin", help="An elevated path (defaults to --protected)")
    p.add_argument("--jwks", help="JWKS URL, enables the algorithm-confusion check")
    p.add_argument("--json", action="store_true", help="Output JSON instead of text")
    p.add_argument("--authorized", action="store_true",
                   help="Confirm you own or are authorized to test this target")
    args = p.parse_args(argv)

    if not args.authorized:
        print("Refusing to run: pass --authorized to confirm you have permission to test\n"
              "this target. Only test systems you own or are explicitly authorized to test.",
              file=sys.stderr)
        return 2

    try:
        token = login(args.url, args.login, args.username, args.password)
    except Exception as exc:
        print(f"Could not log in to obtain a token: {exc}", file=sys.stderr)
        return 1

    target = Target(args.url, token, args.protected, args.admin, args.jwks)
    findings = run_audit(target)

    if args.json:
        print(report.to_json(findings))
    else:
        print(report.to_text(findings, args.url))

    # Exit non-zero if any vulnerability was found (useful in CI).
    return 1 if any(f.status == "vulnerable" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
