import time
from pathlib import Path

import pytest

from advisory_tracer.cache import DiskCache


def test_roundtrip(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path)
    cache.set("ns", "key", {"a": [1, 2]})

    assert cache.get("ns", "key") == {"a": [1, 2]}
    assert cache.get("ns", "other") is None
    assert cache.get("other-ns", "key") is None


def test_ttl_expiry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = DiskCache(tmp_path)
    cache.set("ns", "key", "value")
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 100)

    assert cache.get("ns", "key", ttl_seconds=200) == "value"
    assert cache.get("ns", "key", ttl_seconds=50) is None
    assert cache.get("ns", "key", ttl_seconds=None) == "value"


def test_corrupt_entry_is_a_miss(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path)
    cache.set("ns", "key", "value")
    next(tmp_path.rglob("*.json")).write_text("{not json", encoding="utf-8")

    assert cache.get("ns", "key") is None
