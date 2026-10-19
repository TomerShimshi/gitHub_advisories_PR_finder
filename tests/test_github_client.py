import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from advisory_tracer.cache import DiskCache
from advisory_tracer.github_client import (
    GitHubAuthError,
    GitHubClient,
    GitHubNotFoundError,
    GitHubRateLimitError,
)

API = "https://api.github.com"


def _client(tmp_path: Path, sleep: Any, cache: bool = True) -> GitHubClient:
    return GitHubClient("token", DiskCache(tmp_path) if cache else None, sleep=sleep)


@respx.mock
def test_sends_token_and_api_headers(tmp_path: Path, no_sleep: Any) -> None:
    route = respx.get(f"{API}/advisories/GHSA-x").respond(json={"ghsa_id": "GHSA-x"})

    _client(tmp_path, no_sleep).get_advisory("GHSA-x")

    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer token"
    assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"


@respx.mock
def test_paginates_with_link_header(tmp_path: Path, no_sleep: Any) -> None:
    next_url = f"{API}/advisories?type=reviewed&per_page=2&after=CURSOR"
    respx.get(next_url).respond(json=[{"ghsa_id": "3"}])
    respx.get(f"{API}/advisories", params={"type": "reviewed", "per_page": "2"}).respond(
        json=[{"ghsa_id": "1"}, {"ghsa_id": "2"}],
        headers={"Link": f'<{next_url}>; rel="next"'},
    )

    ids = [a["ghsa_id"] for a in _client(tmp_path, no_sleep).iter_advisories(per_page=2)]

    assert ids == ["1", "2", "3"]


@respx.mock
def test_second_run_is_served_from_cache(tmp_path: Path, no_sleep: Any) -> None:
    route = respx.get(f"{API}/advisories/GHSA-x").respond(json={"ghsa_id": "GHSA-x"})
    _client(tmp_path, no_sleep).get_advisory("GHSA-x")

    second = _client(tmp_path, no_sleep)
    assert second.get_advisory("GHSA-x") == {"ghsa_id": "GHSA-x"}

    assert route.call_count == 1
    assert second.stats.network_calls == 0
    assert second.stats.cache_hits == 1


@respx.mock
def test_expired_cache_refetches(tmp_path: Path, no_sleep: Any) -> None:
    route = respx.get(f"{API}/advisories/GHSA-x").respond(json={"ghsa_id": "GHSA-x"})
    _client(tmp_path, no_sleep).get_advisory("GHSA-x")

    _client(tmp_path, no_sleep).get_advisory("GHSA-x", ttl_seconds=0)

    assert route.call_count == 2


@respx.mock
def test_bad_token_raises_auth_error(tmp_path: Path, no_sleep: Any) -> None:
    respx.get(f"{API}/advisories/GHSA-x").respond(401, json={"message": "Bad credentials"})

    with pytest.raises(GitHubAuthError, match="GITHUB_TOKEN"):
        _client(tmp_path, no_sleep).get_advisory("GHSA-x")


@respx.mock
def test_not_found(tmp_path: Path, no_sleep: Any) -> None:
    respx.get(f"{API}/advisories/GHSA-x").respond(404, json={"message": "Not Found"})

    with pytest.raises(GitHubNotFoundError):
        _client(tmp_path, no_sleep).get_advisory("GHSA-x")


@respx.mock
def test_retries_server_errors_then_succeeds(tmp_path: Path, no_sleep: Any) -> None:
    respx.get(f"{API}/advisories/GHSA-x").mock(
        side_effect=[httpx.Response(502), httpx.Response(200, json={"ok": True})]
    )
    client = _client(tmp_path, no_sleep)

    assert client.get_advisory("GHSA-x") == {"ok": True}
    assert no_sleep.calls == [1]
    assert client.stats.network_calls == 2


@respx.mock
def test_retries_network_errors(tmp_path: Path, no_sleep: Any) -> None:
    respx.get(f"{API}/advisories/GHSA-x").mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(200, json={"ok": True})]
    )

    assert _client(tmp_path, no_sleep).get_advisory("GHSA-x") == {"ok": True}


@respx.mock
def test_waits_for_short_rate_limit(tmp_path: Path, no_sleep: Any) -> None:
    respx.get(f"{API}/advisories/GHSA-x").mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "5"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    assert _client(tmp_path, no_sleep).get_advisory("GHSA-x") == {"ok": True}
    assert no_sleep.calls == [5.0]


@respx.mock
def test_long_rate_limit_fails_fast(tmp_path: Path, no_sleep: Any) -> None:
    reset = str(int(time.time()) + 3600)
    respx.get(f"{API}/advisories/GHSA-x").respond(
        403,
        headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset},
        json={"message": "API rate limit exceeded"},
    )

    with pytest.raises(GitHubRateLimitError):
        _client(tmp_path, no_sleep).get_advisory("GHSA-x")
    assert no_sleep.calls == []


def _compare_commit(sha: str) -> dict[str, Any]:
    return {
        "sha": sha,
        "commit": {"message": "m", "committer": {"date": "d"}, "author": {"name": "x"}},
        "parents": [{"sha": "p", "url": "u"}],
        "author": {"login": "someone"},
    }


@respx.mock
def test_compare_paginates_and_trims(tmp_path: Path, no_sleep: Any) -> None:
    url = f"{API}/repos/o/r/compare/v1...v2"
    respx.get(url, params={"page": "1"}).respond(
        json={
            "status": "ahead",
            "total_commits": 3,
            "files": [{"patch": "x" * 1000}],
            "commits": [_compare_commit("1"), _compare_commit("2")],
        }
    )
    respx.get(url, params={"page": "2"}).respond(
        json={"status": "ahead", "total_commits": 3, "commits": [_compare_commit("3")]}
    )
    client = _client(tmp_path, no_sleep)

    result = client.compare("o", "r", "v1", "v2", max_commits=2)  # One page of 2.
    assert [c["sha"] for c in result["commits"]] == ["1", "2"]

    result = _client(tmp_path, no_sleep).compare("o", "r", "v1", "v2", max_commits=100)

    assert "files" not in result
    assert result["commits"][0] == {
        "sha": "1",
        "commit": {"message": "m", "committer": {"date": "d"}},
        "parents": [{"sha": "p"}],
    }


@pytest.mark.parametrize(
    ("status", "expected"), [("behind", True), ("identical", True), ("diverged", False)]
)
@respx.mock
def test_is_ancestor_compares_branch_to_commit(
    tmp_path: Path, no_sleep: Any, status: str, expected: bool
) -> None:
    route = respx.get(f"{API}/repos/o/r/compare/main...abc").respond(
        json={"status": status, "total_commits": 0, "commits": []}
    )

    assert _client(tmp_path, no_sleep).is_ancestor("o", "r", "abc", "main") is expected
    assert route.called


@respx.mock
def test_unknown_sha_422_is_not_found(tmp_path: Path, no_sleep: Any) -> None:
    respx.get(f"{API}/repos/o/r/commits/abc").respond(
        422, json={"message": "No commit found for SHA: abc"}
    )

    with pytest.raises(GitHubNotFoundError):
        _client(tmp_path, no_sleep).get_commit("o", "r", "abc")


@respx.mock
def test_forbidden_without_rate_limit_is_auth_error(tmp_path: Path, no_sleep: Any) -> None:
    respx.get(f"{API}/advisories/GHSA-x").respond(403, json={"message": "Resource not accessible"})

    with pytest.raises(GitHubAuthError):
        _client(tmp_path, no_sleep).get_advisory("GHSA-x")
