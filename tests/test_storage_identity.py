"""Credential-retrieval filtering checks for db.query_credentials (#6).

Runnable offline with no real ChromaDB:
    python tests/test_storage_identity.py

The ChromaStore CRUD identity fixes (#7) are covered by test_ml_modules.py
(TestSharedMemory.test_update_finding / test_delete_by_uuid), which needs
chromadb installed to run.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _FakeCollection:
    def __init__(self):
        self._meta = []

    def count(self):
        return len(self._meta)

    def query(self, query_texts, n_results):
        return {"metadatas": [self._meta[:n_results]]}


class _FakeClient:
    def __init__(self, *a, **k):
        self._c = _FakeCollection()

    def get_or_create_collection(self, *a, **k):
        return self._c


# db is imported against a fake chromadb, but only while this module's tests run.
# The stub must NOT be installed at import time: pytest imports every test module
# during collection, before any test runs, so a module-level
# `sys.modules["chromadb"] = fake` would poison the whole session and break every
# other test that needs the real chromadb. setup_module/teardown_module install
# and restore it around this module only.
db = None
_orig_chromadb = None


def setup_module(module):
    global db, _orig_chromadb
    _orig_chromadb = sys.modules.get("chromadb")
    _fake = types.ModuleType("chromadb")
    _fake.PersistentClient = lambda *a, **k: _FakeClient()
    sys.modules["chromadb"] = _fake
    sys.modules.pop("db", None)  # force db to (re)bind the fake
    import db as _db
    db = _db


def teardown_module(module):
    sys.modules.pop("db", None)
    if _orig_chromadb is None:
        sys.modules.pop("chromadb", None)
    else:
        sys.modules["chromadb"] = _orig_chromadb


def test_query_credentials_filters_non_credentials():
    db._get_collection()._meta = [
        {"title": "Extracted credential", "evidence": "jsmith:Password123!"},
        {"title": "Open port", "evidence": "80/tcp open http"},
        {"title": "SQL payload", "evidence": "admin' OR 1=1--"},
    ]
    assert db.query_credentials(n_results=5) == ["jsmith:Password123!"]


def test_looks_like_credential():
    assert db._looks_like_credential("user password: hunter2")
    assert db._looks_like_credential("NTLM hash recovered")
    assert not db._looks_like_credential("80/tcp open http")
    assert not db._looks_like_credential("admin' OR 1=1--")


if __name__ == "__main__":
    setup_module(None)
    test_query_credentials_filters_non_credentials()
    test_looks_like_credential()
    print("ok")
