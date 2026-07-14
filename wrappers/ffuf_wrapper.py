import subprocess
import os

# Primary: SecLists common.txt — proper real-world wordlist
# Fallback: original test.txt if SecLists not installed
SECLIST_PATH = "/usr/share/seclists/Discovery/Web-Content/common.txt"
FALLBACK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists", "test.txt"
)
WORDLIST = SECLIST_PATH if os.path.exists(SECLIST_PATH) else FALLBACK_PATH

def run_ffuf(url: str, timeout: int = 120) -> str:
    """
    Runs FFUF against a target URL and returns raw stdout output.
    Uses SecLists common.txt for real endpoint discovery.
    """
    result = subprocess.run(
        [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", WORDLIST
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    output = result.stdout + result.stderr

    if result.returncode != 0:
        raise RuntimeError(
            f"ffuf exited with code {result.returncode}: "
            f"{result.stderr.strip()[:500]}"
        )

    return result.stdout + result.stderr
