# parsers/nikto_parser.py

from schema import Finding

def parse_nikto(output: str, task_id: str):

    findings = []

    lines = output.splitlines()

    for line in lines:

        if "X-Frame-Options" in line:

            findings.append(
                Finding(
                    task_id=task_id,
                    surface="web",
                    title="Missing X-Frame-Options Header",
                    description=line,
                    severity="Medium",
                    evidence=line,
                    remediation="Configure X-Frame-Options header."
                )
            )

        elif "Server leaks" in line:

            findings.append(
                Finding(
                    task_id=task_id,
                    surface="web",
                    title="Information Disclosure",
                    description=line,
                    severity="Low",
                    evidence=line,
                    remediation="Hide server version information."
                )
            )

    return findings