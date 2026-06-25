import os
import time
from schema import Task
from agents.web_agent_demo import run_web_agent_demo
from stubs import mock_network_agent
import reporting_agent
from db import query_findings

def run_pipeline_demo():
    print("="*75)
    print("🚀 ARIA PROJECT: END-TO-END PIPELINE DEMO")
    print("="*75)
    
    target_scope = "192.168.1.0/24 internal network and http://demo-dvwa.local"
    print(f"\n[*] INITIATING PENTEST ON SCOPE: {target_scope}")
    time.sleep(1.5)

    print("\n[*] PHASE 1: ORCHESTRATOR PLANNING (Simulated)")
    # Hardcoded tasks to allow running the demo without burning API credits
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
        findings = run_web_agent_demo(t)
        print(f"[+] Web Agent finished. Parsed {len(findings)} tools and stored findings in ChromaDB.")
        
    print("\n[*] PHASE 3: CROSS-SURFACE CORRELATION (ChromaDB Handoff)")
    time.sleep(1.5)
    print("[+] Querying ChromaDB memory for credentials, hashes, or injection vectors...")
    
    cred_results = query_findings("credential password hash SQL injection admin")
    found_creds = []
    
    if cred_results and cred_results.get('documents') and cred_results['documents'][0]:
        found_creds = cred_results['documents'][0]
        print(f"[!] Discovered {len(found_creds)} potential contextual clues from Web surface:")
        for idx, cred in enumerate(found_creds):
            print(f"    - Match {idx+1}: {cred[:70]}...")
    else:
        print("[-] No credentials found.")

    print("\n[*] PHASE 4: NETWORK & AD AGENT EXECUTION")
    time.sleep(1)
    network_tasks = [t for t in tasks if t.type in ["network", "ad"]]
    for t in network_tasks:
        print(f"\n[+] Executing Network Agent on {t.target}...")
        if found_creds:
            print(f"[+] Passing previously discovered web context to Network Agent...")
        finding_ids = mock_network_agent(t)
        print(f"[+] Network Agent finished. Stored {len(finding_ids)} findings in ChromaDB.")
        
    print("\n[*] PHASE 5: REPORT GENERATION")
    time.sleep(1)
    # We call run(use_dummy=False) so it pulls the exact findings we just generated in this demo
    reporting_agent.run(use_dummy=False)
    
    print("\n" + "="*75)
    print("✅ ARIA DEMO COMPLETE. Final structured report saved to 'aria_report.md'.")
    print("="*75)

if __name__ == "__main__":
    run_pipeline_demo()