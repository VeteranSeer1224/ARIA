# parsers/ffuf_parser.py


from schema import Finding

def parse_ffuf(output: str, task_id: str):
    findings = []

    lines = output.splitlines()

    for line in lines:

        # Match any successful endpoint discovered by FFUF
        if "Status: 200" in line:

            endpoint = line.split("[")[0].strip()

            finding = Finding(
                task_id=task_id,
                surface="web",
                title="Hidden Endpoint Discovered",
                description=f"Discovered endpoint {endpoint}",
                severity="Medium",
                evidence=line,
                remediation="Review endpoint exposure and restrict access if unnecessary."
            )

            findings.append(finding)
import re
from schema import Finding

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def parse_ffuf(output: str, task_id: str):
    findings = []

    for line in output.splitlines():
        clean = _ANSI.sub("", line)

        if "Status: 200" not in clean:
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
