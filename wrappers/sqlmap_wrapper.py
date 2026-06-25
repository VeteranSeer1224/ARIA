import subprocess

<<<<<<< HEAD
def run_sqlmap(url: str) -> str:
=======
def run_sqlmap(url: str, timeout: int = 300) -> str:
>>>>>>> origin/main
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
<<<<<<< HEAD
        text=True
    )

=======
        text=True,
        timeout=timeout
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"sqlmap exited with code {result.returncode}: {result.stderr.strip()}"
        )

>>>>>>> origin/main
    return result.stdout + result.stderr