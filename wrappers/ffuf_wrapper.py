import subprocess

def run_ffuf(url: str) -> str:
    """
    Runs FFUF against a target URL and returns raw output.
    """

    result = subprocess.run(
        [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", "wordlists/test.txt"
        ],
        capture_output=True,
        text=True
    )

    return result.stdout + result.stderr