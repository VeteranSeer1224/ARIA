import time
from schema import Task
from agents.web_agent_demo import run_web_agent_demo
from stubs import mock_network_agent, mock_ad_agent
import reporting_agent
from db import query_credentials, clear_findings

def run_pipeline_demo():
    print("=" * 75)
    print("ARIA PROJECT: END-TO-END PIPELINE DEMO")
    print("=" * 75)

    print("\n[*] Clearing ChromaDB for a clean demo run...")
    clear_findings()

    target_scope = "192.168.1.0/24 internal network and http://demo-dvwa.local"
    print(f"\n[*] INITIATING PENTEST ON SCOPE: {target_scope}")
    time.sleep(1.5)

    print("\n[*] PHASE 1: ORCHESTRATOR PLANNING (Simulated)")
    tasks = [
        Task(type="web", target="http://demo-dvwa.local"),
        Task(type="network", target="192.168.1.0/24")
    ]
    time.sleep(1)
    for t in tasks:
        print(f"  -> Generated Task: {t.type.upper()} targeting {t.target}")

    print("\n[*] PHASE 2: WEB AGENT EXECUTION")
    time.sleep(1)
    web_tasks = [t for t in tasks if t.type == "web"]
    for t in web_tasks:
        t.status = "in_progress"
        print(f"\n[+] Executing Web Agent Demo on {t.target}...")
        try:
            findings = run_web_agent_demo(t)
            t.status = "completed"
            print(f"[+] Web Agent finished. Stored {len(findings)} findings in ChromaDB.")
        except Exception as e:
            t.status = "failed"
            print(f"[!] Web Agent failed: {e}")

    print("\n[*] PHASE 3: CROSS-SURFACE CORRELATION (ChromaDB Handoff)")
    time.sleep(1.5)
    found_creds = []
    if web_tasks:
        print("[+] Querying ChromaDB memory for credentials, hashes, or injection vectors...")
        found_creds = query_credentials(n_results=5)
        if found_creds:
            print(f"[!] Discovered {len(found_creds)} credential(s) from Web surface:")
            for idx, cred in enumerate(found_creds):
                print(f"    - Evidence {idx+1}: {cred[:70]}...")
        else:
            print("[-] No credentials found.")

    print("\n[*] PHASE 4: NETWORK & AD AGENT EXECUTION")
    time.sleep(1)
    network_tasks = [t for t in tasks if t.type in ["network", "ad"]]
    for t in network_tasks:
        print(f"\n[+] Executing Network/AD Agent on {t.target}...")
        if found_creds:
            print(f"[+] Passing {len(found_creds)} credential hint(s) to Network Agent...")
        try:
            if t.type == "network":
                findings = mock_network_agent(t, found_creds=found_creds)
            elif t.type == "ad":
                findings = mock_ad_agent(t)
            t.status = "completed"
            print(f"[+] Agent finished. Stored {len(findings)} findings in ChromaDB.")
        except Exception as e:
            t.status = "failed"
            print(f"[!] Agent failed: {e}")

    print("\n[*] PHASE 5: REPORT GENERATION")
    time.sleep(1)
    reporting_agent.run(use_dummy=False)

    print("\n" + "=" * 75)
    print("ARIA DEMO COMPLETE. Final structured report saved to 'aria_report.md'.")
    print("=" * 75)

if __name__ == "__main__":
    run_pipeline_demo()
