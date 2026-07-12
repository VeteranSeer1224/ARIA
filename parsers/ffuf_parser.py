# parsers/ffuf_parser.py

import re
from schema import Finding

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_STATUS_RE = re.compile(r"\[Status:\s*(\d+)")

# Map status code ranges to (severity, title_suffix, remediation)
def _classify_status(code: int):
    if code in (200, 204):
        return ("Medium",
                "Accessible Endpoint Discovered",
                "Review endpoint exposure and restrict access if unnecessary.")
    if code in (301, 302, 307):
        return ("Low",
                "Redirect Discovered",
                "Confirm the redirect target is intentional and not an open redirect.")
    if code in (401, 403):
        return ("Low",
                "Auth-Protected Endpoint Discovered",
                "Verify authentication controls are correctly enforced.")
    return ("Low",
            "Endpoint Discovered",
            "Review endpoint exposure and restrict access if unnecessary.")


def parse_ffuf(output: str, task_id: str):
    findings = []
    for line in output.splitlines():
        clean = _ANSI.sub("", line)
        if "[Status:" not in clean:
            continue
        endpoint = clean.split("[")[0].strip() or "(unknown)"
        status_match = _STATUS_RE.search(clean)
        code = int(status_match.group(1)) if status_match else 0
        severity, title_suffix, remediation = _classify_status(code)
        findings.append(Finding(
            task_id=task_id,
            surface="web",
            title=f"{title_suffix}: {endpoint}",
            description=f"FFUF discovered endpoint '{endpoint}' (HTTP {code}).",
            severity=severity,
            evidence=clean,
            remediation=remediation,
        ))
    return findings
