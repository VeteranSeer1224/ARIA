"""Scanner result-correctness checks: SQLMap parsing and web-agent failure reporting.

Runnable offline with no network and no real tools:
    python tests/test_scanner_correctness.py
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.sqlmap_parser import parse_sqlmap
from schema import Task

# Stub the storage layer so importing the web agent does not pull in chromadb;
# these checks exercise parsing and failure control flow, not persistence.
# Installed in setup_module (not at import time) so it never leaks into the rest
# of the session: pytest imports every test module during collection, so a
# module-level sys.modules swap would replace db for unrelated tests too.
_orig_db = None


def setup_module(module):
    global _orig_db
    _orig_db = sys.modules.get("db")
    _fake_db = types.ModuleType("db")
    _fake_db.add_finding = lambda _f: None
    sys.modules["db"] = _fake_db
    sys.modules.pop("agents.web_agent", None)  # rebind the fake db on next import


def teardown_module(module):
    sys.modules.pop("agents.web_agent", None)
    if _orig_db is None:
        sys.modules.pop("db", None)
    else:
        sys.modules["db"] = _orig_db


def _raise(msg):
    def _f(*_args, **_kwargs):
        raise RuntimeError(msg)
    return _f


def test_sqlmap_parser_rejects_negative():
    negative = (
        "[INFO] testing for SQL injection on GET parameter 'id'\n"
        "[WARNING] GET parameter 'id' does not seem to be injectable"
    )
    assert parse_sqlmap(negative, "T1") == [], "negative output must yield no findings"


def test_sqlmap_parser_accepts_positive():
    injection_point = (
        "sqlmap identified the following injection point(s):\n"
        "Parameter: id (GET)\n    Type: boolean-based blind"
    )
    out = parse_sqlmap(injection_point, "T1")
    assert len(out) == 1 and out[0].severity == "Critical"

    vulnerable = "GET parameter 'id' is vulnerable. Do you want to keep testing the others?"
    assert len(parse_sqlmap(vulnerable, "T1")) == 1, "'is vulnerable' must be detected"


def test_web_agent_raises_when_a_tool_fails():
    import agents.web_agent as wa

    # Snapshot and restore the module globals we override, so this test does not
    # leave the web agent's parsers/wrappers stubbed out for other test modules.
    names = ("add_finding", "parse_ffuf", "parse_nikto", "parse_sqlmap",
             "run_ffuf", "run_nikto", "run_sqlmap")
    orig = {name: getattr(wa, name) for name in names}
    try:
        wa.add_finding = lambda _f: None
        wa.parse_ffuf = lambda _o, _t: []
        wa.parse_nikto = lambda _o, _t: []
        wa.parse_sqlmap = lambda _o, _t: []
        wa.run_nikto = lambda _t: ""
        wa.run_sqlmap = lambda _t: ""
        wa.run_ffuf = _raise("ffuf boom")

        task = Task(type="web", target="http://example.test")
        try:
            wa.run_web_agent(task)
        except RuntimeError as e:
            assert "FFUF" in str(e), "aggregated error must name the failed tool"
        else:
            raise AssertionError("run_web_agent must raise when a tool fails")

        # Clean run: all tools succeed -> returns findings, no raise.
        wa.run_ffuf = lambda _t: ""
        assert wa.run_web_agent(task) == []
    finally:
        for name, value in orig.items():
            setattr(wa, name, value)


if __name__ == "__main__":
    setup_module(None)
    test_sqlmap_parser_rejects_negative()
    test_sqlmap_parser_accepts_positive()
    test_web_agent_raises_when_a_tool_fails()
    print("ok")
