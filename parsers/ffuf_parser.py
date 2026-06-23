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

    return findings