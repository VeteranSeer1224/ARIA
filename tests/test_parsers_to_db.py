import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from parsers.ffuf_parser import parse_ffuf
from parsers.nikto_parser import parse_nikto
from parsers.sqlmap_parser import parse_sqlmap

from db import add_finding

TASK_ID = "test-task"

with open("sample_outputs/ffuf_output.txt") as f:
    findings = parse_ffuf(f.read(), TASK_ID)

for finding in findings:
    add_finding(finding)

with open("sample_outputs/nikto_output.txt") as f:
    findings = parse_nikto(f.read(), TASK_ID)

for finding in findings:
    add_finding(finding)

with open("sample_outputs/sqlmap_output.txt") as f:
    findings = parse_sqlmap(f.read(), TASK_ID)

for finding in findings:
    add_finding(finding)

print("Pipeline test complete.")