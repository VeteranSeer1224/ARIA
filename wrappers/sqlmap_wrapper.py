import subprocess

<<<<<<< HEAD
<<<<<<< HEAD
def run_sqlmap(url: str) -> str:
=======
def run_sqlmap(url: str, timeout: int = 300) -> str:
>>>>>>> origin/main
=======
def run_sqlmap(url: str) -> str:
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
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
=======
        text=True
    )

>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
    return result.stdout + result.stderr