import subprocess

def run_sqlmap(url: str, timeout: int = 300) -> str:
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

    return result.stdout + result.stderr