from schema import Task, Finding
from db import add_finding
from datetime import datetime

def mock_web_agent(task: Task) -> list[str]: # [cite: 26]
    """Simulates P2's Web Agent."""
    print(f"[Web Agent Stub] Executing task on {task.target}...")
    
    # Hardcoded fake finding
    mock_finding = Finding(
        task_id=task.id,
        surface="web",
        title="SQL Injection in Login Panel",
        description="Blind SQLi found in the 'username' parameter. Extracted admin hash.",
        severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence="Parameter: username\nPayload: admin' OR 1=1--",
        remediation="Use parameterized queries."
    )
    
    add_finding(mock_finding)
    task.status = "completed"
    task.completed_at = datetime.utcnow()
    
    return [mock_finding.id]

def mock_network_agent(task: Task) -> list[str]: # [cite: 26]
    """Simulates P3's Network/AD Agent."""
    print(f"[Network Agent Stub] Executing task on {task.target}...")
    
    mock_finding = Finding(
        task_id=task.id,
        surface="network",
        title="Anonymous SMB Share Access",
        description="IPC$ and C$ shares are readable without authentication.",
        severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        evidence="smbclient -N -L \\\\target_ip",
        remediation="Disable anonymous SMB access."
    )
    
    add_finding(mock_finding)
    task.status = "completed"
    task.completed_at = datetime.utcnow()
    
    return [mock_finding.id]