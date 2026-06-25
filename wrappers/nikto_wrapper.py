import subprocess

def run_nikto(url: str, timeout: int = 300) -> str:
    """
    Runs Nikto against a target URL and returns raw output.
    """

    result = subprocess.run(
        [
            "nikto",
            "-h",
            url
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    # Nikto exits non-zero when it finds vulnerabilities (normal success case).
    # Only treat it as a failure if there is no output at all.
    output = result.stdout + result.stderr
    if not output.strip():
        raise RuntimeError(
            f"nikto produced no output (exit code {result.returncode})"
        )

    return output
