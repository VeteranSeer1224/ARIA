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

    # sqlmap exits non-zero even on a successful detection, so a bad exit code
    # only counts as a real failure when none of the positive markers are present.
    if result.returncode != 0:
        success_markers = (
            "is vulnerable",
            "sqlmap identified the following injection point",
        )
        if not any(m in output.lower() for m in success_markers):
            raise RuntimeError(
                f"sqlmap exited with code {result.returncode} and no success "
                f"markers were found.\nOutput:\n{output[:2000]}"
            )

    return output
