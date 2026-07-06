import subprocess


def run_sqlmap(url: str, timeout: int = 300) -> str:
    """
    Runs SQLMap against a target URL and returns raw output.

    Note: SQLMap exits non-zero even when it successfully finds
    an injection. We only raise on genuine failure signals in output.
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
        failure_markers = [
            "unable to connect",
            "connection timed out",
            "no parameter(s) found",
            "could not be resolved",
        ]

        lowered = output.lower()
        found_success = any(m in lowered for m in success_markers)
        found_failure = any(m in lowered for m in failure_markers)

        if found_failure and not found_success:
            raise RuntimeError(
                f"sqlmap exited with code {result.returncode}: "
                f"{result.stderr.strip()[:500]}"
            )

    return output
