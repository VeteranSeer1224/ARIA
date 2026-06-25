import subprocess
<<<<<<< HEAD
<<<<<<< HEAD

def run_ffuf(url: str) -> str:
=======
import os

WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "wordlists", "test.txt"
)

def run_ffuf(url: str, timeout: int = 120) -> str:
>>>>>>> origin/main
=======

def run_ffuf(url: str) -> str:
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
    """
    Runs FFUF against a target URL and returns raw output.
    """

    result = subprocess.run(
        [
            "ffuf",
            "-u", f"{url}/FUZZ",
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
            "-w", "wordlists/test.txt"
        ],
        capture_output=True,
        text=True
    )

<<<<<<< HEAD
=======
            "-w", WORDLIST
        ],
        capture_output=True,
        text=True,
        timeout=timeout
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"ffuf exited with code {result.returncode}: {result.stderr.strip()}"
        )

>>>>>>> origin/main
=======
>>>>>>> d7b09bd77237d9a109218e5d7207740fe0fca8f5
    return result.stdout + result.stderr