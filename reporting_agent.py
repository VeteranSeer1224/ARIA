import os
import sys
import argparse
from datetime import datetime
from cvss import CVSS3
from db import collection


def get_severity_label(meta):
    """
    Computes the real CVSS 3.1 base score from the severity vector string
    using the official formula (via the cvss library), instead of guessing
    from keywords. Falls back to UNKNOWN if the vector is missing or invalid.
    """
    severity_str = meta.get("severity", "")
    try:
        c = CVSS3(severity_str)
        score = float(c.base_score)
        label = c.severities()[0].upper()
        return label, score
    except Exception:
        return "UNKNOWN", None


def read_real_findings():
    results = collection.get(include=["documents", "metadatas"])
    ids = results.get("ids", [])
    metadatas = results.get("metadatas", [])
    documents = results.get("documents", [])

    findings = []
    for chroma_id, meta, doc in zip(ids, metadatas, documents):
        label, score = get_severity_label(meta)
        findings.append({
            "id": chroma_id,
            "title": meta.get("title", "Untitled finding"),
            "surface": meta.get("surface", "unknown"),
            "severity_label": label,
            "cvss_score": score,
            "severity_raw": meta.get("severity", ""),
            "evidence": meta.get("evidence", "Not recorded"),
            "remediation": meta.get("remediation", "Not recorded"),
            "description": doc
        })
    return findings


def generate_report(findings):
    if not findings:
        return (
            f"# ARIA Penetration Test Report\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            "No findings were present in ChromaDB at the time this report was generated.\n"
        )

    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "NONE": [], "UNKNOWN": []}
    for f in findings:
        groups.setdefault(f["severity_label"], []).append(f)

    report = f"""# ARIA Penetration Test Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {len(groups['CRITICAL'])} |
| High     | {len(groups['HIGH'])} |
| Medium   | {len(groups['MEDIUM'])} |
| Low      | {len(groups['LOW'])} |
| Unknown  | {len(groups['NONE']) + len(groups['UNKNOWN'])} |
| **Total**| **{len(findings)}** |

---

## Findings by Severity
"""

    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]:
        group = groups[label]
        if group:
            report += f"\n### {label} Findings\n"
            for f in group:
                score_display = f["cvss_score"] if f["cvss_score"] is not None else "N/A"
                report += f"""
#### [{f['id']}] {f['title']}
- **Surface:** {f['surface'].upper()}
- **CVSS Score:** {score_display} ({label})
- **Vector:** {f['severity_raw']}
- **Description:** {f['description']}
- **Evidence:** {f['evidence']}
- **Remediation:** {f['remediation']}
"""

    report += """
---

## Remediation Recommendations

Review each finding above for specific remediation guidance. Patch critical and high
severity issues first, then re-scan to confirm fixes.

---
*Report generated automatically by ARIA Reporting Agent v1*
"""
    return report


def run():
    print("[*] Reporting Agent v1 started...")

    findings = read_real_findings()
    print(f"[*] Retrieved {len(findings)} findings from ChromaDB")

    report = generate_report(findings)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "aria_report.md")

    try:
        with open(output_path, "w") as f:
            f.write(report)
        print(f"[*] Report saved to {output_path}")
    except OSError as e:
        print(f"[!] Failed to write report: {e}")
        sys.exit(1)

    print("[*] Done!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    run()
