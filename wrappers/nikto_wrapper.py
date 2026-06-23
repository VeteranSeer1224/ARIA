import subprocess

def run_nikto(url: str) -> str:
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
        text=True
    )

    return result.stdout + result.stderr