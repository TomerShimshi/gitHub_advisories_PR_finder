"""Small on-disk JSON cache so reruns don't repeat network calls (or, later, paid LLM calls)."""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class DiskCache:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.directory / namespace / digest[:2] / f"{digest}.json"

    def get(self, namespace: str, key: str, ttl_seconds: float | None = None) -> Any | None:
        """Return the cached value, or None if missing or older than ttl_seconds."""
        path = self._path(namespace, key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        if ttl_seconds is not None and time.time() - entry["stored_at"] > ttl_seconds:
            return None
        return entry["value"]

    def set(self, namespace: str, key: str, value: Any) -> None:
        path = self._path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"stored_at": time.time(), "key": key, "value": value})
        # Write to a temp file and rename, so a crash never leaves a half-written entry.
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
