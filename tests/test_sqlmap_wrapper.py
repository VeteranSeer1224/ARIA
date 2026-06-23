import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

from wrappers.sqlmap_wrapper import run_sqlmap

output = run_sqlmap(
    "http://testphp.vulnweb.com/listproducts.php?cat=1"
)

print("=== SQLMAP RAW OUTPUT ===")
print(output)