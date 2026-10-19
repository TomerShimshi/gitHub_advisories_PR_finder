from typing import Any

import pytest

from advisory_tracer.models import Advisory, parse_github_repo


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/pallets/flask", "pallets/flask"),
        ("https://github.com/pallets/flask/", "pallets/flask"),
        ("https://github.com/pallets/flask.git", "pallets/flask"),
        ("https://github.com/pallets/flask/commit/abc123", "pallets/flask"),
        ("http://github.com/a-b/c.d_e/pull/1", "a-b/c.d_e"),
        ("https://gitlab.com/pallets/flask", None),
        ("https://github.com/github/advisory-database/pull/1", None),
        ("https://evil.example/https://github.com/a/b", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_github_repo(url: str | None, expected: str | None) -> None:
    repo = parse_github_repo(url)
    assert (repo.full_name if repo else None) == expected


def test_from_api_maps_fields(advisory_payload: dict[str, Any]) -> None:
    advisory = Advisory.from_api(advisory_payload)

    assert advisory is not None
    assert advisory.ghsa_id == "GHSA-2222-3333-4444"
    assert advisory.repo.full_name == "example-org/example-lib"
    assert advisory.cwes == ["CWE-22"]
    assert advisory.vulnerabilities[0].package == "example-lib"
    assert advisory.vulnerabilities[0].first_patched_version == "1.4.2"


def test_from_api_accepts_patched_version_object(advisory_payload: dict[str, Any]) -> None:
    advisory_payload["vulnerabilities"][0]["first_patched_version"] = {"identifier": "1.4.2"}

    advisory = Advisory.from_api(advisory_payload)

    assert advisory is not None
    assert advisory.vulnerabilities[0].first_patched_version == "1.4.2"


def test_from_api_falls_back_to_references(advisory_payload: dict[str, Any]) -> None:
    advisory_payload["source_code_location"] = ""

    advisory = Advisory.from_api(advisory_payload)

    assert advisory is not None
    assert advisory.repo.full_name == "example-org/example-lib"


def test_from_api_without_github_repo_returns_none(advisory_payload: dict[str, Any]) -> None:
    advisory_payload["source_code_location"] = "https://gitlab.com/x/y"
    advisory_payload["references"] = ["https://nvd.nist.gov/vuln/detail/CVE-2024-00001"]

    assert Advisory.from_api(advisory_payload) is None
