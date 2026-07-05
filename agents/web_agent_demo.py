import os
from schema import Task
from db import add_finding

from parsers.ffuf_parser import parse_ffuf
from parsers.nikto_parser import parse_nikto
from parsers.sqlmap_parser import parse_sqlmap

_SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sample_outputs")


def run_web_agent_demo(task: Task):

    all_findings = []

    with open(os.path.join(_SAMPLE_DIR, "ffuf_output.txt")) as f:
        ffuf_output = f.read()

    for finding in parse_ffuf(ffuf_output, task.id):
        add_finding(finding)
        all_findings.append(finding)

    with open(os.path.join(_SAMPLE_DIR, "nikto_output.txt")) as f:
        nikto_output = f.read()

    for finding in parse_nikto(nikto_output, task.id):
        add_finding(finding)
        all_findings.append(finding)

    with open(os.path.join(_SAMPLE_DIR, "sqlmap_output.txt")) as f:
        sqlmap_output = f.read()

    for finding in parse_sqlmap(sqlmap_output, task.id):
        add_finding(finding)
        all_findings.append(finding)

    return all_findings