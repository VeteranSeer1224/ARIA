from schema import Task
from db import add_finding

from wrappers.ffuf_wrapper import run_ffuf
from wrappers.nikto_wrapper import run_nikto
from wrappers.sqlmap_wrapper import run_sqlmap

from parsers.ffuf_parser import parse_ffuf
from parsers.nikto_parser import parse_nikto
from parsers.sqlmap_parser import parse_sqlmap


def run_web_agent(task: Task):
    """
    Executes web reconnaissance and vulnerability assessment.

    Flow:
    FFUF -> Parser -> ChromaDB
    Nikto -> Parser -> ChromaDB
    SQLMap -> Parser -> ChromaDB
    """

    print("=" * 60)
    print(f"[Web Agent] Starting task {task.id}")
    print(f"[Web Agent] Target: {task.target}")
    print("=" * 60)

    all_findings = []

    # --------------------------------------------------
    # FFUF
    # --------------------------------------------------
    try:
        print("\n[Web Agent] Running FFUF...")

        ffuf_output = run_ffuf(task.target)

        ffuf_findings = parse_ffuf(
            ffuf_output,
            task.id
        )

        print(
            f"[Web Agent] FFUF produced "
            f"{len(ffuf_findings)} findings."
        )

        for finding in ffuf_findings:
            add_finding(finding)
            all_findings.append(finding)

    except Exception as e:
        print(f"[Web Agent] FFUF Error: {e}")

    # --------------------------------------------------
    # NIKTO
    # --------------------------------------------------
    try:
        print("\n[Web Agent] Running Nikto...")

        nikto_output = run_nikto(task.target)

        nikto_findings = parse_nikto(
            nikto_output,
            task.id
        )

        print(
            f"[Web Agent] Nikto produced "
            f"{len(nikto_findings)} findings."
        )

        for finding in nikto_findings:
            add_finding(finding)
            all_findings.append(finding)

    except Exception as e:
        print(f"[Web Agent] Nikto Error: {e}")

    # --------------------------------------------------
    # SQLMAP
    # --------------------------------------------------
    try:
        print("\n[Web Agent] Running SQLMap...")

        sqlmap_output = run_sqlmap(task.target)

        sqlmap_findings = parse_sqlmap(
            sqlmap_output,
            task.id
        )

        print(
            f"[Web Agent] SQLMap produced "
            f"{len(sqlmap_findings)} findings."
        )

        for finding in sqlmap_findings:
            add_finding(finding)
            all_findings.append(finding)

    except Exception as e:
        print(f"[Web Agent] SQLMap Error: {e}")

    print("\n" + "=" * 60)
    print(
        f"[Web Agent] Completed. "
        f"Stored {len(all_findings)} findings."
    )
    print("=" * 60)

    return all_findings