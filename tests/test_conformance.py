"""Backend conformance suite (design §14.1): op semantics, pagination, batch
limits, unicode payloads, idempotent deletes. InMemoryBackend is the reference;
the AgentCore adapter runs the same suite live via aws/live_validation.py."""

import pytest

from memwarden.backends.inmemory import InMemoryBackend

NS = "tenants/acme/conformance"


@pytest.fixture(params=["inmemory"])
def backend(request):
    return InMemoryBackend()


def test_put_get_roundtrip(backend):
    rid = backend.put(NS, "hello world", {"actor_id": "a1"})
    rec = backend.get(NS, rid)
    assert rec.record_id == rid and rec.content == "hello world"
    assert rec.namespace == NS and rec.meta["actor_id"] == "a1"


def test_get_missing_returns_none(backend):
    assert backend.get(NS, "nonexistent") is None


def test_retrieve_scoped_to_namespace(backend):
    backend.put(NS, "alpha beta gamma", {})
    backend.put(NS + "/other", "alpha beta delta", {})
    recs = backend.retrieve(NS, "alpha beta", k=8)
    assert all(r.namespace == NS for r in recs) and len(recs) == 1


def test_retrieve_k_limit(backend):
    for i in range(12):
        backend.put(NS, f"common token doc{i}", {})
    assert len(backend.retrieve(NS, "common token", k=5)) == 5


def test_list_pagination(backend):
    ids = {backend.put(NS, f"doc {i}", {}) for i in range(250)}
    seen, cursor = set(), None
    for _ in range(10):
        page = backend.list(NS, cursor)
        seen.update(r.record_id for r in page.records)
        cursor = page.cursor
        if cursor is None:
            break
    assert seen == ids


def test_delete_idempotent(backend):
    rid = backend.put(NS, "to delete", {})
    assert backend.delete(NS, rid) is True
    assert backend.delete(NS, rid) is False       # second delete is a no-op
    assert backend.get(NS, rid) is None


def test_batch_delete_counts(backend):
    rids = [backend.put(NS, f"d{i}", {}) for i in range(5)]
    assert backend.batch_delete(NS, rids + ["missing"]) == 5


def test_unicode_payloads(backend):
    content = "díacrítics, 中文, עברית, emoji 🎯, and combining s̈"
    rid = backend.put(NS, content, {})
    assert backend.get(NS, rid).content == content


def test_list_by_actor_across_namespaces(backend):
    backend.put(NS, "a's note", {"actor_id": "a"})
    backend.put(NS + "/x", "a's other note", {"actor_id": "a"})
    backend.put(NS, "b's note", {"actor_id": "b"})
    assert len(list(backend.list_by_actor("a"))) == 2
