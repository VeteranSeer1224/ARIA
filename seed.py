"""
Developer-only script. Seeds dummy findings into ChromaDB for local testing.
Run: python seed.py
Do NOT run against a production chroma_store.
"""
from schema import Finding
from db import add_finding

DUMMY_FINDINGS = [
    Finding(
        id="F001", task_id="T001", surface="web",
        title="SQL Injection in /login endpoint",
        description="The username parameter is not sanitised, allowing SQL injection.",
        severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence="SQLmap extracted 847 rows from the users table.",
        remediation="Use parameterised queries.",
    ),
    Finding(
        id="F002", task_id="T002", surface="network",
        title="SMB Vulnerability on 192.168.10.12",
        description="Unpatched SMB service vulnerable to RCE.",
        severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence="Metasploit gained command execution via SMB exploit.",
        remediation="Patch SMB. Disable SMBv1.",
    ),
    Finding(
        id="F003", task_id="T003", surface="web",
        title="Directory Listing Enabled on /backup",
        description="The /backup directory is publicly browsable.",
        severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        evidence="FFUF discovered /backup/db.sql.",
        remediation="Disable directory listing.",
    ),
    Finding(
        id="F004", task_id="T004", surface="ad",
        title="Weak credentials valid across domain",
        description="Credential admin:hunter2 works on 14 domain machines.",
        severity="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        evidence="CrackMapExec confirmed credential valid on 14 machines.",
        remediation="Enforce strong password policy and MFA.",
    ),
]

if __name__ == "__main__":
    for finding in DUMMY_FINDINGS:
        add_finding(finding)
    print(f"[*] Seeded {len(DUMMY_FINDINGS)} dummy findings into ChromaDB")
