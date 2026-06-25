import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from wrappers.ffuf_wrapper import run_ffuf

output = run_ffuf("http://testphp.vulnweb.com")

print("=== FFUF RAW OUTPUT ===")
print(output)