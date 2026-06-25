import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from parsers.sqlmap_parser import parse_sqlmap

with open("sample_outputs/sqlmap_output.txt", "r") as f:
    sqlmap_output = f.read()

findings = parse_sqlmap(sqlmap_output, "task_sqlmap")

print("=== SQLMAP PARSER TEST ===")
print("Findings found:", len(findings))

for finding in findings:
    print("\n----------------")
    print("Title:", finding.title)
    print("Description:", finding.description)
    print("Severity:", finding.severity)
    print("Evidence:", finding.evidence)
    print("Remediation:", finding.remediation)