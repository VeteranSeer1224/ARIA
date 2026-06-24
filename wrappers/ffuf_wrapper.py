import subprocess
import os

WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists", "test.txt"
)

def run_ffuf(url: str, timeout: int = 120) -> str:
    """
    Runs FFUF against a target URL and returns raw output.
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

    if result.returncode != 0:
        raise RuntimeError(
            f"ffuf exited with code {result.returncode}: {result.stderr.strip()}"
        )

    return result.stdout + result.stderr