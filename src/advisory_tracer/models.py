"""Data models: the advisory as we use it, and a first draft of the YAML report schema."""

import re
from collections import Counter
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# Matches https://github.com/<owner>/<repo>[/...] and captures owner and repo.
_GITHUB_REPO_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+?)(?:\.git)?(?:/|$|#|\?)"
)
# Repos that host advisory data, not the vulnerable code itself.
_NON_PROJECT_REPOS = {("github", "advisory-database"), ("pypa", "advisory-database")}


class RepoRef(BaseModel):
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self.full_name}"


def parse_github_repo(url: str | None) -> RepoRef | None:
    """Extract owner/repo from a github.com URL, or None if it isn't one."""
    if not url:
        return None
    match = _GITHUB_REPO_RE.match(url.strip())
    if not match:
        return None
    owner, name = match.groups()
    if (owner.lower(), name.lower()) in _NON_PROJECT_REPOS:
        return None
    return RepoRef(owner=owner, name=name)


class Vulnerability(BaseModel):
    ecosystem: str | None = None
    package: str | None = None
    vulnerable_version_range: str | None = None
    first_patched_version: str | None = None
    vulnerable_functions: list[str] = Field(default_factory=list)


class Advisory(BaseModel):
    ghsa_id: str
    cve_id: str | None = None
    html_url: str | None = None
    summary: str = ""
    description: str = ""
    severity: str | None = None
    cwes: list[str] = Field(default_factory=list)
    published_at: datetime | None = None
    repo: RepoRef
    references: list[str] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "Advisory | None":
        """Build from a GitHub global advisory payload. Returns None if no GitHub repo is known."""
        references = [r for r in (data.get("references") or []) if isinstance(r, str)]
        repo = parse_github_repo(data.get("source_code_location")) or _repo_from_references(
            references
        )
        if repo is None:
            return None
        return cls(
            ghsa_id=data["ghsa_id"],
            cve_id=data.get("cve_id"),
            html_url=data.get("html_url"),
            summary=data.get("summary") or "",
            description=data.get("description") or "",
            severity=data.get("severity"),
            cwes=[c["cwe_id"] for c in data.get("cwes") or [] if c.get("cwe_id")],
            published_at=data.get("published_at"),
            repo=repo,
            references=references,
            vulnerabilities=[_parse_vulnerability(v) for v in data.get("vulnerabilities") or []],
        )


def _repo_from_references(references: list[str]) -> RepoRef | None:
    """Fallback: the repo most often linked from the references (e.g. commit or PR links)."""
    repos = [r for r in map(parse_github_repo, references) if r is not None]
    if not repos:
        return None
    (owner, name), _ = Counter((r.owner, r.name) for r in repos).most_common(1)[0]
    return RepoRef(owner=owner, name=name)


def _parse_vulnerability(data: dict[str, Any]) -> Vulnerability:
    package = data.get("package") or {}
    patched = data.get("first_patched_version")
    # The API has returned this both as a plain string and as {"identifier": "..."}.
    if isinstance(patched, dict):
        patched = patched.get("identifier")
    return Vulnerability(
        ecosystem=package.get("ecosystem"),
        package=package.get("name"),
        vulnerable_version_range=data.get("vulnerable_version_range"),
        first_patched_version=patched,
        vulnerable_functions=data.get("vulnerable_functions") or [],
    )


# --- Report schema (draft; filled in by Plans 2-4) ---------------------------------------------


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class Verdict(StrEnum):
    UNCHECKED = "unchecked"
    VERIFIED = "verified"
    PLAUSIBLE = "plausible"
    REJECTED = "rejected"


class CommitFinding(BaseModel):
    """One answer (e.g. 'the fix commit'), with the evidence behind it. sha=None means not found."""

    sha: str | None = None
    commit_url: str | None = None
    pr_number: int | None = None
    pr_url: str | None = None
    confidence: Confidence = Confidence.NONE
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""
    verdict: Verdict = Verdict.UNCHECKED
    verdict_reason: str = ""


class AdvisoryReport(BaseModel):
    ghsa_id: str
    cve_id: str | None = None
    repo: str
    summary: str = ""
    fix: CommitFinding = Field(default_factory=CommitFinding)
    introduced: CommitFinding = Field(default_factory=CommitFinding)
    cost_usd: float = 0.0
    error: str | None = None
