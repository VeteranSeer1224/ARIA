# parsers/ffuf_parser.py

import re
from schema import Finding

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def parse_ffuf(output: str, task_id: str):
    findings = []
    for line in output.splitlines():
        clean = _ANSI.sub("", line)
        if "[Status:" not in clean:
            continue
        endpoint = clean.split("[")[0].strip()
        findings.append(Finding(
            task_id=task_id,
            surface="web",
            title="Hidden Endpoint Discovered",
            description=f"Discovered endpoint: {endpoint}",
            severity="Medium",
            evidence=clean,
            remediation="Review endpoint exposure and restrict access if unnecessary."
        ))

    return findings
