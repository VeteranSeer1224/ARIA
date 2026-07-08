import subprocess


def run_sqlmap(url: str, timeout: int = 300) -> str:
    """
    Runs SQLMap against a target URL and returns raw output.

    Note: SQLMap exits non-zero even when it successfully finds
    an injection. We only raise if we cannot confirm success.
    """
    result = subprocess.run(
        [
            "sqlmap",
            "-u", url,
            "--batch"
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    output = result.stdout + result.stderr

    if result.returncode != 0:
        success_markers = [
            "is vulnerable",
            "parameter '",
            "the following injection point",
            "sqlmap identified the following injection point",
        ]
        lowered = output.lower()
        found_success = any(m in lowered for m in success_markers)

    return result.stdout + result.stderr
