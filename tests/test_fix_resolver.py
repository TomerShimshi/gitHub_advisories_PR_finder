from pathlib import Path
from typing import Any

import pytest
import respx

from advisory_tracer.cache import DiskCache
from advisory_tracer.fix_resolver import FixResolver, _release_range, _tag_version
from advisory_tracer.github_client import GitHubClient
from advisory_tracer.models import Advisory, Confidence

API = "https://api.github.com/repos/org/proj"
MAIN_FIX = "a" * 40
BACKPORT = "b" * 40
MERGE = "c" * 40


def _advisory(references: list[str], **extra: Any) -> Advisory:
    data: dict[str, Any] = {
        "ghsa_id": "GHSA-2222-3333-4444",
        "cve_id": "CVE-2024-1",
        "summary": "Path traversal in the loader",
        "description": "The loader joins user paths without sanitizing them.",
        "source_code_location": "https://github.com/org/proj",
        "references": references,
        "vulnerabilities": [
            {"package": {"ecosystem": "pip", "name": "proj"}, "first_patched_version": "1.2.0"}
        ],
    }
    data.update(extra)
    advisory = Advisory.from_api(data)
    assert advisory is not None
    return advisory


def _commit(sha: str, title: str, date: str = "2024-01-01T00:00:00Z") -> dict[str, Any]:
    return {"sha": sha, "commit": {"message": f"{title}\n\nbody", "committer": {"date": date}}}


def _pr(number: int, merge_sha: str | None, merged: bool = True) -> dict[str, Any]:
    return {
        "number": number,
        "html_url": f"https://github.com/org/proj/pull/{number}",
        "merged_at": "2024-01-02T00:00:00Z" if merged else None,
        "merge_commit_sha": merge_sha,
    }


@pytest.fixture
def resolver(tmp_path: Path, no_sleep: Any) -> FixResolver:
    return FixResolver(GitHubClient("t", DiskCache(tmp_path), sleep=no_sleep))


def _mock_repo(default_branch: str = "main") -> None:
    respx.get(API).respond(json={"default_branch": default_branch})


def _mock_on_branch(sha: str, on_branch: bool) -> None:
    status = "behind" if on_branch else "diverged"
    respx.get(f"{API}/compare/main...{sha}").respond(
        json={"status": status, "total_commits": 0, "commits": []}
    )


@respx.mock
def test_linked_commits_with_backport(resolver: FixResolver) -> None:
    _mock_repo()
    respx.get(f"{API}/commits/{MAIN_FIX}").respond(
        json=_commit(MAIN_FIX, "Sanitize loader paths", "2024-01-01T00:00:00Z")
    )
    respx.get(f"{API}/commits/{BACKPORT}").respond(
        json=_commit(BACKPORT, "Backport loader fix (#7)", "2024-01-03T00:00:00Z")
    )
    respx.get(f"{API}/commits/{MAIN_FIX}/pulls").respond(json=[_pr(5, MAIN_FIX)])
    respx.get(f"{API}/commits/{BACKPORT}/pulls").respond(json=[_pr(7, BACKPORT)])
    _mock_on_branch(MAIN_FIX, True)
    _mock_on_branch(BACKPORT, False)

    fix = resolver.resolve(
        _advisory(
            [
                f"https://github.com/org/proj/commit/{BACKPORT}",
                f"https://github.com/org/proj/commit/{MAIN_FIX}",
            ]
        )
    )

    assert fix.primary.sha == MAIN_FIX
    assert fix.primary.pr_number == 5
    assert fix.primary.on_default_branch is True
    assert fix.primary.confidence == Confidence.HIGH
    assert [c.sha for c in fix.commits] == [MAIN_FIX, BACKPORT]  # Default branch first.
    assert fix.commits[1].pr_number == 7


@respx.mock
def test_linked_pr_without_linked_commit_uses_merge_commit(resolver: FixResolver) -> None:
    _mock_repo()
    respx.get(f"{API}/pulls/9").respond(json=_pr(9, MERGE))
    respx.get(f"{API}/pulls/10").respond(json=_pr(10, None, merged=False))
    respx.get(f"{API}/commits/{MERGE}").respond(json=_commit(MERGE, "Fix traversal (#9)"))
    _mock_on_branch(MERGE, True)

    fix = resolver.resolve(
        _advisory(["https://github.com/org/proj/pull/9", "https://github.com/org/proj/pull/10"])
    )

    assert fix.primary.sha == MERGE
    assert fix.primary.pr_number == 9
    assert "PR #10 was never merged" in " ".join(fix.notes)


@respx.mock
def test_private_fork_merge_is_explained(resolver: FixResolver) -> None:
    _mock_repo()
    respx.get(f"{API}/commits/{MAIN_FIX}").respond(
        json=_commit(MAIN_FIX, "Merge pull request from GHSA-2222-3333-4444")
    )
    respx.get(f"{API}/commits/{MAIN_FIX}/pulls").respond(json=[])
    _mock_on_branch(MAIN_FIX, True)

    fix = resolver.resolve(_advisory([f"https://github.com/org/proj/commit/{MAIN_FIX}"]))

    assert fix.primary.pr_number is None
    assert any("private security fork" in e for e in fix.primary.evidence)


@respx.mock
def test_unknown_linked_commit_is_noted_not_guessed(resolver: FixResolver) -> None:
    respx.get(f"{API}/commits/{MAIN_FIX}").respond(422, json={"message": "No commit found"})
    respx.get("https://api.github.com/search/commits").respond(json={"items": []})
    respx.get("https://api.github.com/search/issues").respond(json={"items": []})
    respx.get(f"{API}/tags").respond(json=[])

    fix = resolver.resolve(_advisory([f"https://github.com/org/proj/commit/{MAIN_FIX}"]))

    assert not fix.found
    assert any(f"commit {MAIN_FIX} not found" in n for n in fix.notes)


@respx.mock
def test_search_fallback_finds_commit_mentioning_the_ghsa(resolver: FixResolver) -> None:
    _mock_repo()
    respx.get("https://api.github.com/search/commits").respond(json={"items": [{"sha": MAIN_FIX}]})
    respx.get("https://api.github.com/search/issues").respond(json={"items": []})
    respx.get(f"{API}/commits/{MAIN_FIX}").respond(json=_commit(MAIN_FIX, "Fix GHSA-2222"))
    respx.get(f"{API}/commits/{MAIN_FIX}/pulls").respond(json=[])
    _mock_on_branch(MAIN_FIX, True)

    fix = resolver.resolve(_advisory([]))

    assert fix.primary.sha == MAIN_FIX
    assert fix.primary.confidence == Confidence.MEDIUM


@respx.mock
def test_release_range_candidates_ranked_by_relevance(resolver: FixResolver) -> None:
    respx.get("https://api.github.com/search/commits").respond(json={"items": []})
    respx.get("https://api.github.com/search/issues").respond(json={"items": []})
    respx.get(f"{API}/tags").respond(
        json=[{"name": n} for n in ("v1.2.0", "v1.1.9", "v1.1.0", "v1.2.0rc1", "nightly")]
    )
    respx.get(f"{API}/compare/v1.1.9...v1.2.0").respond(
        json={
            "status": "ahead",
            "total_commits": 3,
            "commits": [
                _commit("1" * 40, "Bump version"),
                _commit("2" * 40, "Update docs"),
                _commit("3" * 40, "Sanitize loader paths against traversal"),
            ],
        }
    )

    fix = resolver.resolve(_advisory([]))

    assert not fix.found
    assert [c.sha[0] for c in fix.candidates] == ["3", "1", "2"]
    assert fix.candidates[0].source == "compare v1.1.9...v1.2.0"
    assert "3 release-range candidate(s)" in fix.notes[-1]


@pytest.mark.parametrize(
    ("tag", "package", "expected"),
    [
        ("v1.2.3", None, "1.2.3"),
        ("1.2.3", None, "1.2.3"),
        ("release-1.2.3", None, "1.2.3"),
        ("proj-1.2.3", "proj", "1.2.3"),
        ("nightly", None, None),
    ],
)
def test_tag_version(tag: str, package: str | None, expected: str | None) -> None:
    version = _tag_version(tag, package)
    assert (str(version) if version else None) == expected


def test_release_range_skips_prereleases_and_other_branches() -> None:
    tags = ["v2.0.6", "v2.0.5", "v1.26.17", "v1.26.16", "v2.0.6rc1"]

    assert _release_range(tags, "1.26.17", None) == ("v1.26.17", "v1.26.16")
    assert _release_range(tags, "2.0.6", None) == ("v2.0.6", "v2.0.5")
    assert _release_range(tags, "9.9.9", None) == (None, "v2.0.6")
