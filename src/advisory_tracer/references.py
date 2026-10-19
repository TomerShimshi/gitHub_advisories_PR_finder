"""Classify the URLs in an advisory's references (fix commits, PRs, release tags, ...)."""

import re
from dataclasses import dataclass, field

from advisory_tracer.models import RepoRef

# SECURITY: references are untrusted. These patterns only accept hex SHAs and numeric PR IDs,
# so values extracted here are safe to put into API URL paths.
_BASE = r"^https?://github\.com/(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)"
_COMMIT_RE = re.compile(_BASE + r"/commits?/(?P<sha>[0-9a-fA-F]{7,40})(?:[/?#.]|$)")
_PULL_RE = re.compile(
    _BASE
    + r"/pull/(?P<number>\d+)(?:/commits/(?P<sha>[0-9a-fA-F]{7,40}))?(?:[/?#.]|$)"
)
_COMPARE_RE = re.compile(_BASE + r"/compare/(?P<base>[^/?#]+?)\.\.\.?(?P<head>[^/?#]+)")
_TAG_RE = re.compile(_BASE + r"/releases/tag/(?P<tag>[^/?#]+)")


@dataclass
class ParsedReferences:
    commit_shas: list[str] = field(default_factory=list)
    pull_numbers: list[int] = field(default_factory=list)
    compares: list[tuple[str, str]] = field(default_factory=list)
    release_tags: list[str] = field(default_factory=list)
    # Links to commits or PRs in other repositories (forks, renamed repos): kept for logging.
    foreign: list[str] = field(default_factory=list)


def parse_references(references: list[str], repo: RepoRef) -> ParsedReferences:
    """Extract fix-related links for `repo`, in reference order, without duplicates."""
    parsed = ParsedReferences()
    for url in references:
        url = url.strip()
        if match := _PULL_RE.match(url):
            if not _same_repo(match, repo):
                parsed.foreign.append(url)
                continue
            _append_unique(parsed.pull_numbers, int(match["number"]))
            if match["sha"]:
                _append_unique(parsed.commit_shas, match["sha"].lower())
        elif match := _COMMIT_RE.match(url):
            if not _same_repo(match, repo):
                parsed.foreign.append(url)
                continue
            _append_unique(parsed.commit_shas, match["sha"].lower())
        elif (match := _COMPARE_RE.match(url)) and _same_repo(match, repo):
            _append_unique(parsed.compares, (match["base"], match["head"]))
        elif (match := _TAG_RE.match(url)) and _same_repo(match, repo):
            _append_unique(parsed.release_tags, match["tag"])
    return parsed


def _same_repo(match: re.Match[str], repo: RepoRef) -> bool:
    # GitHub owner and repo names are case-insensitive.
    return (match["owner"].lower(), match["repo"].lower()) == (
        repo.owner.lower(),
        repo.name.lower(),
    )


def _append_unique[T](items: list[T], value: T) -> None:
    if value not in items:
        items.append(value)
