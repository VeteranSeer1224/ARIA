import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from schema import Finding
from db import add_finding


def run_nmap_scan(target: str, extra_flags: str = "-sV -Pn", timeout: int = 300) -> str:
    """
    Runs Nmap against a target and returns raw XML output as a string.
    -Pn skips ping check (required for Windows targets that block ICMP).
    Only scan targets you own or have explicit authorization to test.
    """
    output_file = "/tmp/nmap_scan.xml"
    command = ["nmap"] + extra_flags.split() + ["-oX", output_file, target]

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            print(f"[!] Nmap exited with error: {result.stderr}")
            return None
        with open(output_file, "r") as f:
            return f.read()
    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out")
        return None
    except FileNotFoundError:
        print("[!] Nmap is not installed or not in PATH")
        return None


def parse_nmap_xml(xml_string: str, task_id: str = "T-NMAP-001") -> list:
    """
    Parses Nmap XML into a list of Finding dicts.
    One finding per open port discovered.
    """
    if not xml_string:
        return []

    findings = []
    root = ET.fromstring(xml_string)

    for host in root.findall("host"):
        address_elem = host.find("address")
        ip = address_elem.get("addr") if address_elem is not None else "unknown"

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id = port.get("portid")
            protocol = port.get("protocol")
            service_elem = port.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""

            # Flag high-risk ports with elevated severity
            high_risk_ports = {"445", "135", "139", "3389", "23", "21"}
            severity = (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
                if port_id in high_risk_ports
                else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
            )

            findings.append({
                "task_id": task_id,
                "surface": "network",
                "title": f"Open port {port_id}/{protocol} ({service_name}) on {ip}",
                "description": (
                    f"Nmap detected open {protocol} port {port_id} running "
                    f"{service_name} {product} {version}".strip()
                ),
                "severity": severity,
                "evidence": (
                    f"nmap -sV -Pn {ip} -> port {port_id}/{protocol} open, "
                    f"service={service_name} {product} {version}".strip()
                ),
                "remediation": (
                    f"Review whether port {port_id} ({service_name}) needs to be "
                    f"exposed. Firewall or disable if unnecessary."
                ),
                "timestamp": datetime.utcnow().isoformat()
            })

    return findings


def save_findings_to_db(findings: list) -> int:
    """Converts dict findings into Finding objects and writes them to ChromaDB."""
    saved = 0
    for f in findings:
        finding_obj = Finding(
            task_id=f["task_id"],
            surface=f["surface"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            evidence=f["evidence"],
            remediation=f["remediation"],
        )
        add_finding(finding_obj)
        saved += 1
    return saved


if __name__ == "__main__":
    target = "192.168.56.101"
    print(f"[*] Running Nmap scan against {target}...")
    xml_output = run_nmap_scan(target)

    if xml_output:
        findings = parse_nmap_xml(xml_output)
        print(f"[*] Parsed {len(findings)} findings")
        for f in findings:
            print(f"    - {f['title']}")
        saved = save_findings_to_db(findings)
        print(f"[*] Saved {saved} findings to ChromaDB")
    else:
        print("[!] No output to parse")
