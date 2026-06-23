# parsers/sqlmap_parser.py

from schema import Finding

def parse_sqlmap(output: str, task_id: str):

    findings = []

    if "injectable" in output.lower():

        findings.append(
            Finding(
                task_id=task_id,
                surface="web",
                title="SQL Injection",
                description="SQLMap identified injectable parameter.",
                severity="Critical",
                evidence=output,
                remediation="Use parameterized queries."
            )
        )

    return findings