import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from parsers.ffuf_parser import parse_ffuf

with open("sample_outputs/ffuf_output.txt", "r") as f:
    ffuf_output = f.read()

findings = parse_ffuf(ffuf_output, "task_ffuf")

print("=== FFUF PARSER TEST ===")
print("Findings found:", len(findings))

for finding in findings:
    print("\n----------------")
    print("Title:", finding.title)
    print("Description:", finding.description)
    print("Severity:", finding.severity)