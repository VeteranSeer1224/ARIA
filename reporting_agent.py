import os
import sys
import argparse
from datetime import datetime
from collections import defaultdict
from cvss import CVSS3
from db import _get_collection


# ── Severity helpers ────────────────────────────────────────────────

# Keyword-to-label mapping for plain-text severity strings emitted by
# the parsers (ffuf, nikto, sqlmap).  The CVSS vector path is tried
# first; this table is the fallback.
_KEYWORD_SEVERITY = {
    "critical": ("CRITICAL", 9.5),
    "high":     ("HIGH",     7.5),
    "medium":   ("MEDIUM",   5.0),
    "low":      ("LOW",      2.5),
    "info":     ("INFORMATIONAL", 0.0),
    "informational": ("INFORMATIONAL", 0.0),
    "none":     ("INFORMATIONAL", 0.0),
}

# Canonical ordering for the report sections.
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]

_SEVERITY_EMOJI = {
    "CRITICAL":      "🔴",
    "HIGH":          "🟠",
    "MEDIUM":        "🟡",
    "LOW":           "🔵",
    "INFORMATIONAL": "⚪",
    "UNKNOWN":       "⚪",
}


def get_severity_label(meta):
    """
    Computes the CVSS 3.1 base score and severity label from the severity
    field in a ChromaDB metadata dict. Accepts both a proper CVSS v3.1
    vector string and a plain-text label (e.g. 'High', 'Medium').
    Falls back to UNKNOWN if missing or unrecognised.
    """
    severity_str = meta.get("severity", "")

    # ── Path 1: proper CVSS vector ──────────────────────────────
    try:
        c = CVSS3(severity_str)
        score = float(c.base_score)
        label = c.severities()[0].upper()
        if label == "NONE":
            label = "INFORMATIONAL"
        return label, score
    except Exception:
        pass

    # ── Path 2: keyword / plain-text fallback ───────────────────
    key = severity_str.lower().strip()
    if key in _KEYWORD_SEVERITY:
        return _KEYWORD_SEVERITY[key]

    # Partial match (e.g. "Medium - XSS")
    for kw, val in _KEYWORD_SEVERITY.items():
        if kw in key:
            return val

    return "UNKNOWN", None


# ── Seed data (testing only) ────────────────────────────────────────

def seed_dummy_data():
    """Only used for testing. Upserts so re-running --seed never crashes."""
    dummy = [
        {
            "id": "F001", "task_id": "T001", "surface": "web",
            "title": "SQL Injection in /login endpoint",
            "description": "The username parameter is not sanitised, allowing SQL injection.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "evidence": "SQLmap extracted 847 rows from the users table.",
            "remediation": "Use parameterised queries.",
        },
        {
            "id": "F002", "task_id": "T002", "surface": "network",
            "title": "SMB Vulnerability on 192.168.10.12",
            "description": "Unpatched SMB service vulnerable to RCE.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "evidence": "Metasploit gained command execution via SMB exploit.",
            "remediation": "Patch SMB. Disable SMBv1.",
        },
        {
            "id": "F003", "task_id": "T003", "surface": "web",
            "title": "Directory Listing Enabled on /backup",
            "description": "The /backup directory is publicly browsable.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "evidence": "FFUF discovered /backup/db.sql.",
            "remediation": "Disable directory listing.",
        },
        {
            "id": "F004", "task_id": "T004", "surface": "ad",
            "title": "Weak credentials valid across domain",
            "description": "Credential admin:hunter2 works on 14 domain machines.",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "evidence": "CrackMapExec confirmed credential valid on 14 machines.",
            "remediation": "Enforce strong password policy and MFA.",
        },
    ]
    for f in dummy:
        _get_collection().upsert(
            documents=[f["description"]],
            metadatas=[{
                "id": f["id"],
                "task_id": f["task_id"],
                "surface": f["surface"],
                "title": f["title"],
                "severity": f["severity"],
                "evidence": f["evidence"],
                "remediation": f["remediation"],
            }],
            ids=[f["id"]]
        )
    print(f"[*] Seeded {len(dummy)} dummy findings into ChromaDB (upsert, safe to re-run)")


# ── ChromaDB reader ────────────────────────────────────────────────

def read_real_findings():
    results = _get_collection().get(include=["documents", "metadatas"])
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


# ── Deduplication ───────────────────────────────────────────────────

def deduplicate(findings):
    """
    Content-based deduplication.  Two findings are considered duplicates
    when they share the same (title, description, surface) tuple.  The
    first occurrence (by insertion order) is kept.
    """
    seen = set()
    unique = []
    for f in findings:
        key = (f["title"], f["description"], f["surface"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── Report generator ───────────────────────────────────────────────

def _build_summary_table(groups, total):
    """Executive summary severity table."""
    rows = []
    for label in _SEVERITY_ORDER:
        count = len(groups.get(label, []))
        emoji = _SEVERITY_EMOJI.get(label, "")
        rows.append(f"| {emoji} {label} | {count} |")
    rows.append(f"| **TOTAL** | **{total}** |")
    header = "| Severity | Count |\n|----------|-------|"
    return header + "\n" + "\n".join(rows)


def _build_surface_table(findings):
    """Breakdown of finding counts per attack surface."""
    counts = defaultdict(int)
    for f in findings:
        counts[f["surface"].upper()] += 1

    if not counts:
        return ""

    header = "| Surface | Findings |\n|---------|----------|"
    rows = [f"| {surface} | {count} |" for surface, count in sorted(counts.items())]
    return header + "\n" + "\n".join(rows)


def generate_report(findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not findings:
        return (
            f"# ARIA Penetration Test Report\n"
            f"Generated: {timestamp}\n\n"
            "No findings were present in ChromaDB at the time this report was generated.\n"
        )

    findings = deduplicate(findings)

    # Group by severity
    groups = defaultdict(list)
    for f in findings:
        groups[f["severity_label"]].append(f)

    # ── Header ──────────────────────────────────────────────────
    report = f"""# ARIA Penetration Test Report
Generated: {timestamp}

---

## Executive Summary

### Findings by Severity
{_build_summary_table(groups, len(findings))}

### Findings by Attack Surface
{_build_surface_table(findings)}

---

## Detailed Findings
"""

    # ── Per-severity sections ───────────────────────────────────
    for label in _SEVERITY_ORDER:
        group = groups.get(label, [])
        if not group:
            continue
        emoji = _SEVERITY_EMOJI.get(label, "")
        report += f"\n### {emoji} {label} Findings\n"
        for f in group:
            score_display = f["cvss_score"] if f["cvss_score"] is not None else "N/A"
            report += f"""
#### [{f['id']}] {f['title']}
- **Surface:** {f['surface'].upper()}
- **CVSS Score:** {score_display} ({label})
- **Vector:** `{f['severity_raw']}`
- **Description:** {f['description']}
- **Evidence:** {f['evidence']}
- **Remediation:** {f['remediation']}
"""

    # ── Footer ──────────────────────────────────────────────────
    report += """
---

## Remediation Roadmap

1. **Immediate** — Patch all CRITICAL and HIGH findings. These represent
   direct paths to data compromise or remote code execution.
2. **Short-term** — Resolve MEDIUM findings (missing headers, exposed
   endpoints) within the next sprint cycle.
3. **Ongoing** — Address LOW and INFORMATIONAL items as part of regular
   hardening reviews.

---
*Report generated automatically by ARIA Reporting Agent v1*
"""
    return report


# ── Entrypoint ──────────────────────────────────────────────────────

def run(use_dummy=False):
    print("[*] Reporting Agent v1 started...")

    if use_dummy:
        seed_dummy_data()

    findings = read_real_findings()
    print(f"[*] Retrieved {len(findings)} findings from ChromaDB")

    report = generate_report(findings)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Write into chroma_store/ — the only path mounted as a volume in
    # docker-compose, so the report survives the container and is visible
    # on the host.
    output_dir = os.path.join(script_dir, "chroma_store")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "aria_report.md")

    try:
        # utf-8 explicit: report embeds emoji; Windows locale (cp1252)
        # would raise UnicodeEncodeError otherwise.
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[*] Report saved to {output_path}")
    except OSError as e:
        print(f"[!] Failed to write report: {e}")
        sys.exit(1)

    print("[*] Done!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", action="store_true", help="Seed dummy findings before generating report")
    args = parser.parse_args()
    run(use_dummy=args.seed)