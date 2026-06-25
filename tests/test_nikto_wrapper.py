import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from wrappers.nikto_wrapper import run_nikto

output = run_nikto("http://testphp.vulnweb.com")

print("=== NIKTO RAW OUTPUT ===")
print(output)