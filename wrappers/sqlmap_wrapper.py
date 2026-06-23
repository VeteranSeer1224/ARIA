import subprocess

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
        text=True
    )

    return result.stdout + result.stderr