# parsers/sqlmap_parser.py

from schema import Finding

<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
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
<<<<<<< HEAD
=======
_EVIDENCE_KEYWORDS = ("injectable", "parameter", "type:", "payload:", "title:")
_MAX_EVIDENCE = 2000


def _extract_evidence(output: str) -> str:
    lines = [
        line for line in output.splitlines()
        if any(kw in line.lower() for kw in _EVIDENCE_KEYWORDS)
    ]
    evidence = "\n".join(lines)
    if len(evidence) > _MAX_EVIDENCE:
        evidence = evidence[:_MAX_EVIDENCE] + "\n[truncated]"
    return evidence or output[:_MAX_EVIDENCE]


def parse_sqlmap(output: str, task_id: str):
    findings = []

    if "injectable" in output.lower():
        findings.append(Finding(
            task_id=task_id,
            surface="web",
            title="SQL Injection",
            description="SQLMap identified an injectable parameter.",
            severity="Critical",
            evidence=_extract_evidence(output),
            remediation="Use parameterised queries and prepared statements."
        ))
>>>>>>> origin/main
=======
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5

    return findings