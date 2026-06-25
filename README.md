# ARIA: Environment Setup & Quickstart Guide

This guide outlines the mandatory environment configuration for all ARIA project members. Every member must complete these steps and verify their local setup before beginning individual tool integration or agent logic development.

## 1. Automated Environment Bootstrap

To ensure consistency across the team, we have provided automated bootstrap scripts located in the `scripts/` directory. These scripts will automatically verify your Python installation, install base offensive tools, set up Ollama, create your shared virtual environment (`venv`), and install all dependencies.

### For Windows (PowerShell)
The Windows bootstrapper checks your Python installation, installs Nmap and Ollama via `winget`, configures a local Python virtual environment, and handles all pip requirements[cite: 10].
```powershell
# Open PowerShell as Administrator and run:
.\scripts\bootstrap.ps1
# From the project root, run:
bash scripts/bootstrap.sh


ollama serve &
    ```
2.  **Pull the LLaMA 3 model:**
```bash
    ollama run llama3
    ```
3.  **Verification:** Send a test prompt to ensure the model produces output before proceeding[cite: 10, 11].

---

## 3. Orchestrator API Setup (DeepSeek)

The Orchestrator agent relies on the DeepSeek API (`deepseek-chat`) via the OpenAI SDK for high-level planning and task routing[cite: 5, 7]. 

1.  Obtain your DeepSeek API key.
2.  Export the key to your environment variables:
```bash
    export DEEPSEEK_API_KEY="your_api_key_here"
    ```
3.  **Verification:** Run `orchestrator.py` to verify a successful API call to `https://api.deepseek.com`[cite: 5].

---

## 4. Shared Vector Memory (ChromaDB)

We use ChromaDB (`chromadb==0.4.24`) for long-term session memory, enabling cross-surface correlation through the `aria_findings` collection[cite: 4, 7]. 

* **Verification:** Review or run `db.py` to ensure the local ChromaDB client initializes properly and can write/query `Finding` schemas safely[cite: 4].

---

## 5. Security Tool Prerequisites by Role

Depending on your track, verify the local installation of your required security tools. Each tool must produce raw output against a local target before any wrapper or parser development begins. *Note: The bootstrap scripts install basic tools like Nmap (via Winget/APT) and web utilities (via APT on Linux), but you must configure your testing sandboxes manually[cite: 10, 11].*

### Web Agent (P2)
* **Target Sandbox:** Install Docker and run **DVWA (Damn Vulnerable Web Application)** locally.
* **Recon & Exploitation:** Verify the installations of **FFUF**, **Nikto**, and **SQLmap**. *(Note: Windows users are highly recommended to run these specific tools via WSL/Ubuntu as they lack native winget packages[cite: 10].)*

### Network/AD Agent (P3)
* **Recon & Exploitation:** Verify the installations of **Nmap** (installed via bootstrapper[cite: 10, 11]) and **CrackMapExec**.
* **Post-Exploitation:** Install the **Metasploit Framework**, configure the RPC listener (`msfrpcd`), and verify Python client connectivity[cite: 11].
* **AD Mapping:** Research and document the installation steps for **BloodHound CE**.

---

## 6. Repository Standards
Please note that local temporary files, virtual environments, packet captures, and output logs must remain out of version control. Ensure your local environment adheres to the rules defined in `.gitignore`[cite: 3]:
* Excludes `venv/`, `__pycache__/`, and `output/`[cite: 3].
* Ignores offensive testing data logs such as `*.pcap`, `*.dmp`, `*.raw`, or arbitrary `*.json` files (excluding explicit allowed assets)[cite: 3].