import base64
from pathlib import Path
from typing import Any

import pytest
import respx

from advisory_tracer import agent_tools
from advisory_tracer.agent_tools import RepoTools
from advisory_tracer.cache import DiskCache
from advisory_tracer.github_client import GitHubClient
from advisory_tracer.models import Advisory, Candidate, FixFinding

API = "https://api.github.com/repos/org/proj"
FIX = "f" * 40
PARENT = "e" * 40
OLD = "a" * 40
PATCH = "@@ -10,3 +10,3 @@\n base = 1\n-full = base + path\n+full = safe_join(base, path)\n end = 2"


def _advisory(**extra: Any) -> Advisory:
    data: dict[str, Any] = {
        "ghsa_id": "GHSA-2222-3333-4444",
        "source_code_location": "https://github.com/org/proj",
        "published_at": "2024-03-31T00:00:00Z",
    }
    data.update(extra)
    advisory = Advisory.from_api(data)
    assert advisory is not None
    return advisory


def _commit(sha: str, title: str, files: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "sha": sha,
        "commit": {"message": title, "committer": {"date": "2024-01-01T00:00:00Z"}},
        "parents": [{"sha": PARENT}],
        "files": files or [],
    }


def _blame_response(start: int, end: int, sha: str, title: str) -> dict[str, Any]:
    ranges = [
        {
            "startingLine": start,
            "endingLine": end,
            "commit": {
                "oid": sha,
                "committedDate": "2020-05-01T00:00:00Z",
                "messageHeadline": title,
            },
        }
    ]
    return {"data": {"repository": {"object": {"blame": {"ranges": ranges}}}}}


@pytest.fixture
def tools(tmp_path: Path, no_sleep: Any) -> RepoTools:
    client = GitHubClient("t", DiskCache(tmp_path), sleep=no_sleep)
    return RepoTools(client, _advisory(), call_budget=5)


@respx.mock
def test_get_vulnerable_lines_includes_blame_owner(tools: RepoTools) -> None:
    files = [{"filename": "pkg/loader.py", "status": "modified", "patch": PATCH}]
    respx.get(f"{API}/commits/{FIX}").respond(json=_commit(FIX, "Fix traversal", files))
    graphql = respx.post("https://api.github.com/graphql").respond(
        json=_blame_response(1, 50, OLD, "Add loader")
    )

    out = tools.get_vulnerable_lines(FIX)

    assert f"parent: {PARENT}" in out
    assert f"L11    {OLD[:12]} - full = base + path" in out
    assert f"{OLD}  2020-05-01  1/0  Add loader" in out
    # Blamed at the fix's parent, for the right file.
    sent = graphql.calls.last.request.read().decode()
    assert PARENT in sent and "pkg/loader.py" in sent


@respx.mock
def test_get_vulnerable_lines_when_fix_only_adds_files(tools: RepoTools) -> None:
    files = [{"filename": "pkg/guard.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x = 1"}]
    respx.get(f"{API}/commits/{FIX}").respond(json=_commit(FIX, "Add guard", files))

    assert "No pre-existing lines touched" in tools.get_vulnerable_lines(FIX)


@respx.mock
def test_get_commit_diff_skips_auxiliary_patches_and_truncates(
    tools: RepoTools, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent_tools, "MAX_DIFF_LINES", 3)
    files = [
        {"filename": "tests/test_loader.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"},
        {"filename": "pkg/loader.py", "status": "modified", "patch": PATCH, "additions": 1},
    ]
    respx.get(f"{API}/commits/{FIX}").respond(json=_commit(FIX, "Fix traversal\n\nbody", files))

    out = tools.get_commit_diff(FIX)

    assert "title: Fix traversal" in out
    assert "tests/test_loader.py +0/-0 (auxiliary)" in out
    assert "--- tests/test_loader.py" not in out
    assert "--- pkg/loader.py" in out
    assert "truncated" in out


@respx.mock
def test_blame_clips_to_requested_range(tools: RepoTools) -> None:
    respx.post("https://api.github.com/graphql").respond(
        json=_blame_response(1, 100, OLD, "Add loader")
    )

    out = tools.blame("pkg/loader.py", PARENT, 10, 12)

    assert f"L10-12       {OLD}" in out


@respx.mock
def test_read_file_numbers_lines(tools: RepoTools) -> None:
    content = base64.b64encode(b"one\ntwo\nthree\n").decode()
    respx.get(f"{API}/contents/pkg/loader.py").respond(
        json={"encoding": "base64", "content": content}
    )

    out = tools.read_file("pkg/loader.py", PARENT, 2, 9)

    assert "lines 2-3 of 3" in out
    assert "     2  two" in out and "     3  three" in out


@respx.mock
def test_file_history(tools: RepoTools) -> None:
    respx.get(f"{API}/commits").respond(json=[_commit(OLD, "Add loader")])

    assert f"{OLD}  2024-01-01  Add loader" in tools.file_history("pkg/loader.py", PARENT)


@respx.mock
def test_find_prs_explains_private_fork_merges(tools: RepoTools) -> None:
    respx.get(f"{API}/commits/{FIX}/pulls").respond(json=[])
    respx.get(f"{API}/commits/{FIX}").respond(json=_commit(FIX, "Merge commit from fork"))

    assert "private security fork" in tools.find_prs(FIX)


@respx.mock
def test_is_ancestor(tools: RepoTools) -> None:
    respx.get(f"{API}/compare/{FIX}...{OLD}").respond(
        json={"status": "behind", "total_commits": 0, "commits": []}
    )

    assert tools.is_ancestor(OLD, FIX) == f"{OLD[:12]} is an ancestor of {FIX[:12]}"


@respx.mock
def test_list_candidates_uses_resolver_candidates_first(tmp_path: Path, no_sleep: Any) -> None:
    fix = FixFinding(candidates=[Candidate(sha=OLD, title="Fix gym check", source="compare")])
    tools = RepoTools(GitHubClient("t", DiskCache(tmp_path), sleep=no_sleep), _advisory(), fix)

    assert f"{OLD}  Fix gym check  [compare]" in tools.list_candidates()


@respx.mock
def test_list_candidates_falls_back_to_date_window(tools: RepoTools) -> None:
    respx.get(API).respond(json={"default_branch": "main"})
    route = respx.get(f"{API}/commits").respond(json=[_commit(OLD, "Harden loader")])

    out = tools.list_candidates()

    assert "Harden loader  [30 days before publication]" in out
    params = route.calls.last.request.url.params
    assert params["since"] == "2024-03-01T00:00:00Z"
    assert params["until"] == "2024-03-31T00:00:00Z"


def _with_ranges(*ranges: tuple[str, str]) -> Advisory:
    return _advisory(
        vulnerabilities=[
            {"package": {"ecosystem": "pip", "name": pkg}, "vulnerable_version_range": rng}
            for pkg, rng in ranges
        ]
    )


@pytest.mark.parametrize(
    ("ranges", "expected"),
    [
        # The lowest bound marks the introduction; a later major line only inherited it.
        (
            [("proj", ">= 1.8.0, < 1.30.0"), ("proj", ">= 2.0.0, < 2.2.0")],
            {"proj": (">=", "1.8.0")},
        ),
        # An unbounded range means every version is affected: no window.
        ([("proj", "< 1.26.17"), ("proj", ">= 2.0.0, < 2.0.6")], {}),
        ([("proj", "> 1.0")], {"proj": (">", "1.0")}),
        ([("a", ">= 1.0"), ("b", "<= 3")], {"a": (">=", "1.0")}),
    ],
)
def test_lowest_lower_bounds(
    ranges: list[tuple[str, str]], expected: dict[str, tuple[str, str]]
) -> None:
    assert agent_tools._lowest_lower_bounds(_with_ranges(*ranges)) == expected


@respx.mock
def test_introduction_window_compares_last_unaffected_to_first_affected(
    tmp_path: Path, no_sleep: Any
) -> None:
    advisory = _with_ranges(("proj", ">= 1.8.0, < 1.30.0"), ("proj", ">= 2.0.0, < 2.2.0"))
    tools = RepoTools(GitHubClient("t", DiskCache(tmp_path), sleep=no_sleep), advisory)
    respx.get(f"{API}/tags").respond(json=[{"name": n} for n in ("v2.0.0", "v1.8.0", "v1.7.1")])
    route = respx.get(f"{API}/compare/v1.7.1...v1.8.0").respond(
        json={
            "status": "ahead",
            "total_commits": 2,
            "commits": [_commit("1" * 40, "Bump version"), _commit(OLD, "Merge commit from fork")],
        }
    )

    out = tools.introduction_window()

    assert route.called
    assert "introduced between v1.7.1 (unaffected) and v1.8.0 (first affected)" in out
    assert out.index(OLD) < out.index("1" * 40)  # Fork merges rank first.


@respx.mock
def test_introduction_window_without_lower_bound(tmp_path: Path, no_sleep: Any) -> None:
    tools = RepoTools(
        GitHubClient("t", DiskCache(tmp_path), sleep=no_sleep), _with_ranges(("proj", "<= 2.9"))
    )

    assert "all versions are affected" in tools.introduction_window()


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda t: t.get_commit_diff("not-a-sha"), "hex commit SHA"),
        (lambda t: t.read_file("../../etc/passwd", PARENT), "not a valid repository file path"),
        (lambda t: t.read_file("/etc/passwd", PARENT), "not a valid repository file path"),
        (lambda t: t.blame("a.py", PARENT, 5, 2), "bad line range"),
        (lambda t: t.blame("a.py", "main", 1, 2), "hex commit SHA"),
    ],
)
def test_bad_inputs_return_errors_without_api_calls(
    tools: RepoTools, call: Any, message: str
) -> None:
    with respx.mock:  # Any request would fail: nothing is mocked.
        out = call(tools)

    assert out.startswith("ERROR: invalid input") and message in out


@respx.mock
def test_api_errors_come_back_as_text(tools: RepoTools) -> None:
    respx.get(f"{API}/commits/{FIX}").respond(404, json={"message": "Not Found"})

    assert tools.get_commit_diff(FIX).startswith("ERROR: not found")


@respx.mock
def test_budget_stops_calls_and_records_them(tools: RepoTools) -> None:
    respx.get(f"{API}/commits").respond(json=[])

    for _ in range(5):
        tools.file_history("pkg/loader.py", PARENT)
    out = tools.file_history("pkg/loader.py", PARENT)

    assert "budget of 5 calls used up" in out
    assert len(tools.calls) == 5
    assert tools.calls[0].tool == "file_history"
    assert tools.calls[0].args == {"path": "pkg/loader.py", "ref": PARENT}
