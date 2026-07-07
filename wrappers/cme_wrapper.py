import shutil
import subprocess
from schema import Finding


def run_cme_scan(target: str, protocol: str = "smb", timeout: int = 120):
    """
    Runs NetExec (nxc) against a target and returns raw output.
    """
    binary = shutil.which("nxc") or shutil.which("crackmapexec")
    if not binary:
        raise RuntimeError("nxc (NetExec) is not installed or not in PATH")

    try:
        result = subprocess.run(
            [binary, protocol, target],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        print("[!] CrackMapExec scan timed out")
        return None, -1


def parse_cme_output(raw_output: str, target: str, task_id: str = "T-CME-001") -> list:
    """
    Parses NetExec SMB output into Finding objects.
    Detects: Null Auth, SMB signing disabled, SMBv1, domain/OS info.
    """
    findings = []

    if not raw_output:
        return findings

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        lowered = line.lower()

        # Null authentication enabled — anyone can enumerate without creds
        if "nullauth:true" in line.replace(" ", "").lower():
            findings.append(Finding(
                task_id=task_id,
                surface="network",
                title=f"Null Authentication enabled on {target}",
                description=(
                    "The target allows SMB connections without credentials (Null Auth). "
                    "This enables unauthenticated enumeration of users, shares, and domain info."
                ),
                severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                evidence=line,
                remediation=(
                    "Disable null session access via Group Policy: "
                    "Network access: Restrict anonymous access to Named Pipes and Shares."
                ),
            ))

        # SMB signing disabled — enables man-in-the-middle attacks
        if "signing:false" in line.replace(" ", "").lower():
            findings.append(Finding(
                task_id=task_id,
                surface="network",
                title=f"SMB Signing disabled on {target}",
                description=(
                    "SMB signing is not enforced on this host. "
                    "This allows NTLM relay attacks where an attacker intercepts "
                    "authentication and relays it to gain unauthorized access."
                ),
                severity="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                evidence=line,
                remediation=(
                    "Enable and require SMB signing via Group Policy: "
                    "Microsoft network server: Digitally sign communications (always)."
                ),
            ))

        # SMBv1 detected — legacy protocol with known critical vulnerabilities
        if "smbv1:true" in line.replace(" ", "").lower():
            findings.append(Finding(
                task_id=task_id,
                surface="network",
                title=f"SMBv1 enabled on {target}",
                description=(
                    "SMBv1 is enabled on this host. This legacy protocol is vulnerable "
                    "to EternalBlue (MS17-010) and other critical exploits."
                ),
                severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                evidence=line,
                remediation="Disable SMBv1 immediately: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            ))

        # General host info line — always capture as informational finding
        if "[*]" in line and ("windows" in lowered or "domain:" in lowered):
            findings.append(Finding(
                task_id=task_id,
                surface="network",
                title=f"SMB host info discovered on {target}",
                description=(
                    "NetExec successfully enumerated host information via SMB. "
                    f"Details: {line}"
                ),
                severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                evidence=line,
                remediation="Review exposed SMB service and restrict access where possible.",
            ))

    return findings


if __name__ == "__main__":
    from db import add_finding
    target = "192.168.56.101"
    print(f"[*] Running NetExec SMB scan against {target}...")
    raw_output, exit_code = run_cme_scan(target)

    print(f"[*] Exit code: {exit_code}")
    if raw_output:
        print(f"[*] Raw output:\n{raw_output}")

    findings = parse_cme_output(raw_output, target)
    print(f"[*] Parsed {len(findings)} findings")
    for f in findings:
        print(f"    - {f.title}")
        add_finding(f)
    print(f"[*] Saved {len(findings)} findings to ChromaDB")
