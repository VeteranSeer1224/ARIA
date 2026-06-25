import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from db import query_findings

results = query_findings("SQL Injection")

print("\n=== QUERY RESULTS ===")
print(results)