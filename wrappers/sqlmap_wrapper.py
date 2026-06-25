import subprocess

def run_sqlmap(url: str, timeout: int = 300) -> str:
def run_sqlmap(url: str) -> str:
    """
    Runs SQLMap against a target URL and returns raw output.
    """

    result = subprocess.run(
        [
            "sqlmap",
            "-u",
            url,
            "--batch"
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"sqlmap exited with code {result.returncode}: {result.stderr.strip()}"
        )

        text=True
    )

    return result.stdout + result.stderr
    return result.stdout + result.stderr