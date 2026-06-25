import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from parsers.nikto_parser import parse_nikto

with open("sample_outputs/nikto_output.txt", "r") as f:
    nikto_output = f.read()

findings = parse_nikto(nikto_output, "task_nikto")

print("=== NIKTO PARSER TEST ===")
print("Findings found:", len(findings))

for finding in findings:
    print("\n----------------")
    print("Title:", finding.title)
    print("Description:", finding.description)
    print("Severity:", finding.severity)