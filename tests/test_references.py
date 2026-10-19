from advisory_tracer.models import RepoRef
from advisory_tracer.references import parse_references

REPO = RepoRef(owner="Org", name="proj")
SHA = "0123456789abcdef0123456789abcdef01234567"


def test_extracts_commits_prs_compares_and_tags() -> None:
    parsed = parse_references(
        [
            f"https://github.com/org/proj/commit/{SHA}",
            "https://github.com/org/proj/commit/abcdef1.patch",
            "https://github.com/org/proj/pull/42",
            f"https://github.com/org/proj/pull/43/commits/{SHA.upper()}",
            "https://github.com/org/proj/compare/v1.0...v1.1",
            "https://github.com/org/proj/releases/tag/v1.1",
            "https://github.com/org/proj/security/advisories/GHSA-2222-3333-4444",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1",
        ],
        REPO,
    )

    assert parsed.commit_shas == [SHA, "abcdef1"]  # Lower-cased and de-duplicated.
    assert parsed.pull_numbers == [42, 43]
    assert parsed.compares == [("v1.0", "v1.1")]
    assert parsed.release_tags == ["v1.1"]
    assert parsed.foreign == []


def test_links_to_other_repos_are_kept_apart() -> None:
    parsed = parse_references(
        [f"https://github.com/someone/fork/commit/{SHA}", "https://github.com/x/y/pull/1"], REPO
    )

    assert parsed.commit_shas == []
    assert parsed.pull_numbers == []
    assert len(parsed.foreign) == 2


def test_rejects_non_hex_or_injected_values() -> None:
    parsed = parse_references(
        [
            "https://github.com/org/proj/commit/not-a-sha",
            "https://github.com/org/proj/commit/abc",  # Too short.
            "https://github.com/org/proj/pull/12abc",
            "https://evil.example/github.com/org/proj/commit/" + SHA,
        ],
        REPO,
    )

    assert parsed.commit_shas == []
    assert parsed.pull_numbers == []
