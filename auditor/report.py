"""Turn findings into a readable report (terminal text or JSON)."""
import json

from auditor.checks import SEVERITY_ORDER

ICON = {"vulnerable": "[VULN]", "safe": "[ok]  ", "error": "[err] ", "info": "[info]"}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (f.status != "vulnerable",
                                           SEVERITY_ORDER.get(f.severity, 9)))


def to_text(findings, target_url):
    out = [f"JWT auditor — results for {target_url}", "=" * 60]
    vulns = [f for f in findings if f.status == "vulnerable"]
    for f in sort_findings(findings):
        out.append(f"{ICON.get(f.status, '[?]')} {f.severity.upper():8} {f.title}")
        out.append(f"        {f.detail}")
        if f.status == "vulnerable" and f.fix:
            out.append(f"        Fix: {f.fix}")
        out.append("")
    out.append("-" * 60)
    out.append(f"{len(vulns)} vulnerability(ies) found across {len(findings)} checks.")
    return "\n".join(out)


def to_json(findings):
    return json.dumps([f.__dict__ for f in findings], indent=2)
