import subprocess


def run_nikto(url: str, timeout: int = 300) -> str:
    """
    Runs Nikto against a target URL and returns raw output.

    Note: Nikto exits non-zero when it finds vulnerabilities — this is
    normal. Only treat as failure if there is no output at all.
    """
    result = subprocess.run(
        [
            "nikto",
            "-h", url
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    output = result.stdout + result.stderr

    if not output.strip():
        raise RuntimeError(
            f"nikto produced no output (exit code {result.returncode})"
        )

    return output
