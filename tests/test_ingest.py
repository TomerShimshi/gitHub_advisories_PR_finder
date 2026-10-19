import copy
import json
from pathlib import Path
from typing import Any

import respx

from advisory_tracer.cache import DiskCache
from advisory_tracer.github_client import GitHubClient
from advisory_tracer.ingest import fetch_advisories, save_advisories

API = "https://api.github.com"


def _variant(base: dict[str, Any], ghsa_id: str, **changes: Any) -> dict[str, Any]:
    data = copy.deepcopy(base)
    data["ghsa_id"] = ghsa_id
    data.update(changes)
    return data


@respx.mock
def test_fetch_filters_and_respects_limit(
    tmp_path: Path, advisory_payload: dict[str, Any], no_sleep: Any
) -> None:
    page = [
        _variant(advisory_payload, "A"),
        _variant(advisory_payload, "B", source_code_location="", references=[]),
        _variant(advisory_payload, "C", withdrawn_at="2024-06-01T00:00:00Z"),
        _variant(advisory_payload, "D"),
        _variant(advisory_payload, "E"),
    ]
    respx.get(f"{API}/advisories").respond(json=page)
    client = GitHubClient("t", DiskCache(tmp_path), sleep=no_sleep)

    result = fetch_advisories(client, ecosystem="pip", limit=2)

    assert [a.ghsa_id for a in result.advisories] == ["A", "D"]
    assert result.skipped == ["B", "C"]
    request = respx.calls.last.request
    assert request.url.params["ecosystem"] == "pip"
    assert request.url.params["type"] == "reviewed"


@respx.mock
def test_fetch_by_ids(tmp_path: Path, advisory_payload: dict[str, Any], no_sleep: Any) -> None:
    respx.get(f"{API}/advisories/X").respond(json=_variant(advisory_payload, "X"))
    respx.get(f"{API}/advisories/Y").respond(json=_variant(advisory_payload, "Y"))
    client = GitHubClient("t", DiskCache(tmp_path), sleep=no_sleep)

    result = fetch_advisories(client, ecosystem=None, limit=10, ids=["X", "Y"])

    assert [a.ghsa_id for a in result.advisories] == ["X", "Y"]


def test_save_writes_one_file_per_advisory(
    tmp_path: Path, advisory_payload: dict[str, Any]
) -> None:
    from advisory_tracer.models import Advisory

    advisory = Advisory.from_api(advisory_payload)
    assert advisory is not None

    target = save_advisories([advisory], tmp_path)

    saved = json.loads((target / "GHSA-2222-3333-4444.json").read_text(encoding="utf-8"))
    assert saved["repo"] == {"owner": "example-org", "name": "example-lib"}
