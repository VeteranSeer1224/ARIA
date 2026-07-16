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

# HTTP status codes to match.  Without -mc, ffuf uses its own auto-calibrated
# default which can include 404s (if the server returns consistent body sizes).
# Explicit codes produce cleaner output: 2xx success, common redirects,
# and auth-protected paths worth investigating.
MATCH_CODES = "200,204,301,302,307,401,403"

def run_ffuf(url: str, timeout: int = 120) -> str:
    """
    Runs FFUF against a target URL and returns raw stdout+stderr output.
    Uses SecLists common.txt for real endpoint discovery.
    Match codes: 200, 204, 301, 302, 307, 401, 403 (explicitly set to avoid
    ffuf's default auto-calibration producing noisy results).
    """
    result = subprocess.run(
        [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", WORDLIST,
            "-mc", MATCH_CODES,
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

    return output
