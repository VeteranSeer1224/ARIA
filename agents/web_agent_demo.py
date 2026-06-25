from schema import Task
from db import add_finding

from parsers.ffuf_parser import parse_ffuf
from parsers.nikto_parser import parse_nikto
from parsers.sqlmap_parser import parse_sqlmap


def run_web_agent_demo(task: Task):

    all_findings = []

    with open("sample_outputs/ffuf_output.txt") as f:
        ffuf_output = f.read()

    ffuf_findings = parse_ffuf(
        ffuf_output,
        task.id
    )

    for finding in ffuf_findings:
        add_finding(finding)
        all_findings.append(finding)

    with open("sample_outputs/nikto_output.txt") as f:
        nikto_output = f.read()

    nikto_findings = parse_nikto(
        nikto_output,
        task.id
    )

    for finding in nikto_findings:
        add_finding(finding)
        all_findings.append(finding)

    with open("sample_outputs/sqlmap_output.txt") as f:
        sqlmap_output = f.read()

    sqlmap_findings = parse_sqlmap(
        sqlmap_output,
        task.id
    )

    for finding in sqlmap_findings:
        add_finding(finding)
        all_findings.append(finding)

    return all_findings