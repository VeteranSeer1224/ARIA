"""Pure, offline checks for ML Planner scope enforcement. No network, no API calls."""
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))

from ml.orchestrator import in_scope
from ml.models import TargetScope

scope = TargetScope(
    domains=["dvwa.local", "http://example.com"],
    ip_ranges=["10.0.0.0/24"],
    exclusions=["admin.dvwa.local", "10.0.0.5"],
)

assert in_scope("dvwa.local", scope) is True, "in-scope domain should pass"
assert in_scope("admin.dvwa.local", scope) is False, "excluded domain should fail"
assert in_scope("evil.com", scope) is False, "out-of-scope domain should fail"
assert in_scope("api.dvwa.local", scope) is True, "subdomain of in-scope domain should pass"
assert in_scope("http://dvwa.local/login", scope) is True, "URL form of in-scope host should pass"
assert in_scope("10.0.0.42", scope) is True, "IP inside in-scope CIDR should pass"
assert in_scope("192.168.1.1", scope) is False, "IP outside all ranges should fail"
assert in_scope("10.0.0.5", scope) is False, "excluded IP should fail"

print("ok")
