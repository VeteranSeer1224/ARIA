# parsers/nikto_parser.py

from schema import Finding

# (keyword, title, severity, remediation)
_RULES = [
    ("X-Frame-Options",  "Missing X-Frame-Options Header",        "Medium", "Set X-Frame-Options: DENY or SAMEORIGIN."),
    ("X-Content-Type",   "Missing X-Content-Type-Options Header", "Low",    "Set X-Content-Type-Options: nosniff."),
    ("X-XSS-Protection", "Missing X-XSS-Protection Header",       "Low",    "Set X-XSS-Protection: 1; mode=block."),
    ("Server leaks",     "Information Disclosure",                 "Low",    "Hide server version information."),
    ("OSVDB-",           "Known Vulnerability (OSVDB)",            "Medium", "Review and patch the referenced vulnerability."),
    ("SQL",              "Potential SQL Injection Surface",         "High",   "Use parameterised queries."),
    ("dangerous",        "Dangerous HTTP Method Enabled",          "High",   "Disable unused HTTP methods (PUT, DELETE, TRACE)."),
    ("outdated",         "Outdated Software Version",              "Medium", "Update software to the latest stable release."),
    ("cookie",           "Cookie Security Issue",                  "Medium", "Set Secure and HttpOnly flags on all cookies."),
    ("SSL",              "SSL/TLS Misconfiguration",               "Medium", "Review SSL/TLS configuration and disable weak ciphers."),
    ("default",          "Default Configuration Exposed",          "Medium", "Remove or restrict default pages and credentials."),
]

_META_PREFIXES = ("+ Target IP", "+ Target Hostname", "+ Target Port",
                  "+ Start Time", "+ End Time", "+ 0 host")


def parse_nikto(output: str, task_id: str):
    findings = []

    for line in output.splitlines():
        if not line.startswith("+ "):
            continue
        if line.startswith(_META_PREFIXES):
            continue

        clean = line.strip()
        clean_lower = clean.lower()
        matched = False

        for keyword, title, severity, remediation in _RULES:
            if keyword.lower() in clean_lower:
                findings.append(Finding(
                    task_id=task_id,
                    surface="web",
                    title=title,
                    description=clean,
                    severity=severity,
                    evidence=clean,
                    remediation=remediation
                ))
                matched = True
                break

        if not matched:
            findings.append(Finding(
                task_id=task_id,
                surface="web",
                title="Web Misconfiguration",
                description=clean,
                severity="Low",
                evidence=clean,
                remediation="Review the reported configuration issue."
            ))

    return findings