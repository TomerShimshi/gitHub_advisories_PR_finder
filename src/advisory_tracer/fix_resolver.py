"""Find the commit(s) and PR(s) that fixed an advisory, using only the GitHub API (no LLM).

Strategy, cheapest and most certain first:
  1. Commits and PRs linked from the advisory's references (high confidence).
  2. Otherwise, commits and merged PRs in the repo that mention the GHSA or CVE ID (medium).
  3. Otherwise, the commits between the last vulnerable and the first patched release tag are
     saved as candidates for the LLM agent. Nothing is guessed here.
"""

import logging
import re
from typing import Any

from packaging.version import InvalidVersion, Version

from advisory_tracer.github_client import GitHubClient, GitHubError, GitHubNotFoundError
from advisory_tracer.models import (
    Advisory,
    Candidate,
    CommitFinding,
    Confidence,
    FixFinding,
    RepoRef,
)
from advisory_tracer.references import parse_references

log = logging.getLogger(__name__)

_MAX_CANDIDATES = 100
# Security-sounding words in a commit title raise its candidate rank.
_SECURITY_HINT_RE = re.compile(
    r"\b(security|vuln|cve|ghsa|xss|csrf|ssrf|inject|travers|sanitiz|escape|exploit|"
    r"bypass|unsafe|overflow|leak|authoriz|permission|privilege|check)",
    re.IGNORECASE,
)
_WORD_RE = re.compile(r"[a-z][a-z0-9_]{2,}")
# Words too common in advisories and commit titles to say anything about relevance.
_STOPWORDS = frozenset(
    """
    the and for not are but can has was its any all add use via new get set see one two may fix
    this that with from when which there their into have been were will allow allows could would
    user users file files code data version versions update fixed fixes issue using used does
    only also other than then some more attacker vulnerability vulnerable affected summary
    details impact patches
    """.split()  # noqa: SIM905 - a word list is easier to read and edit than 70 quoted strings
)
_TAG_PREFIXES = ("release-", "release_", "version-", "rel-", "v")
# Titles GitHub gives merges from a security advisory's temporary private fork.
_PRIVATE_FORK_MERGE_RE = re.compile(r"^Merge (pull request|commit) from (GHSA-|fork\b)")


class FixResolver:
    def __init__(self, client: GitHubClient) -> None:
        self._client = client

    def resolve(self, advisory: Advisory) -> FixFinding:
        repo = advisory.repo
        refs = parse_references(advisory.references, repo)
        result = FixFinding()
        if refs.foreign:
            result.notes.append(f"ignored links to other repositories: {', '.join(refs.foreign)}")

        commits = self._from_references(repo, refs.commit_shas, refs.pull_numbers, result.notes)
        if not commits:
            commits = self._from_search(repo, advisory, result.notes)
        if not commits:
            result.candidates = self._release_candidates(repo, advisory, refs.release_tags, result)
            result.notes.append(
                f"no fix commit found; {len(result.candidates)} release-range candidate(s) "
                "saved for the agent"
            )
            return result

        default_branch = self._default_branch(repo, result.notes)
        for finding in commits:
            finding.on_default_branch = self._on_branch(repo, finding.sha, default_branch)
        result.commits = sorted(commits, key=_commit_sort_key)
        result.primary = _choose_primary(result.commits, advisory)
        return result

    # --- Tier 1: links in the advisory -----------------------------------------------------------

    def _from_references(
        self, repo: RepoRef, shas: list[str], pull_numbers: list[int], notes: list[str]
    ) -> list[CommitFinding]:
        findings: dict[str, CommitFinding] = {}
        for sha in shas:
            finding = self._commit_finding(
                repo, sha, Confidence.HIGH, "commit linked in the advisory references", notes
            )
            if finding and finding.sha:
                findings.setdefault(finding.sha, finding)

        linked_prs: dict[int, dict[str, Any]] = {}
        for number in pull_numbers:
            try:
                pr = self._client.get_pull(repo.owner, repo.name, number)
            except GitHubNotFoundError:
                notes.append(f"linked PR #{number} does not exist")
                continue
            if not pr.get("merged_at"):
                notes.append(f"linked PR #{number} was never merged; ignored")
                continue
            linked_prs[number] = pr

        for finding in findings.values():
            self._attach_pr(repo, finding, linked_prs)

        # A linked PR that none of the linked commits belongs to: its merge commit is a fix.
        attached = {f.pr_number for f in findings.values()}
        for number, pr in linked_prs.items():
            if number in attached or not pr.get("merge_commit_sha"):
                continue
            finding = self._commit_finding(
                repo,
                pr["merge_commit_sha"],
                Confidence.HIGH,
                f"merge commit of PR #{number}, which is linked in the advisory references",
                notes,
            )
            if finding and finding.sha and finding.sha not in findings:
                _set_pr(finding, pr)
                findings[finding.sha] = finding
        return list(findings.values())

    # --- Tier 2: search for the advisory IDs ------------------------------------------------------

    def _from_search(
        self, repo: RepoRef, advisory: Advisory, notes: list[str]
    ) -> list[CommitFinding]:
        findings: dict[str, CommitFinding] = {}
        for advisory_id in filter(None, (advisory.ghsa_id, advisory.cve_id)):
            try:
                hits = self._client.search_commits(f'"{advisory_id}" repo:{repo.full_name}')
                prs = self._client.search_issues(
                    f'"{advisory_id}" repo:{repo.full_name} is:pr is:merged'
                )
            except GitHubError as exc:
                notes.append(f"search for {advisory_id} failed: {exc}")
                continue
            for hit in hits:
                finding = self._commit_finding(
                    repo, hit["sha"], Confidence.MEDIUM,
                    f"commit message mentions {advisory_id} (GitHub search)", notes,
                )
                if finding and finding.sha:
                    self._attach_pr(repo, finding, {})
                    findings.setdefault(finding.sha, finding)
            for item in prs:
                pr = self._client.get_pull(repo.owner, repo.name, item["number"])
                if not pr.get("merge_commit_sha"):
                    continue
                finding = self._commit_finding(
                    repo, pr["merge_commit_sha"], Confidence.MEDIUM,
                    f"merge commit of PR #{item['number']}, which mentions {advisory_id} "
                    "(GitHub search)",
                    notes,
                )
                if finding and finding.sha and finding.sha not in findings:
                    _set_pr(finding, pr)
                    findings[finding.sha] = finding
        return list(findings.values())

    # --- Tier 3: candidates from the release range -----------------------------------------------

    def _release_candidates(
        self, repo: RepoRef, advisory: Advisory, release_tags: list[str], result: FixFinding
    ) -> list[Candidate]:
        try:
            tags = self._client.list_tags(repo.owner, repo.name)
        except GitHubError as exc:
            result.notes.append(f"could not list tags: {exc}")
            return []

        # Patched releases: from the affected-version data, else from release tags the advisory
        # links (some advisories leave first_patched_version empty).
        patched: list[tuple[str, str | None]] = [
            (v.first_patched_version, v.package)
            for v in advisory.vulnerabilities
            if v.first_patched_version
        ] or [(tag, None) for tag in release_tags]

        candidates: dict[str, Candidate] = {}
        for patched_version, package in dict.fromkeys(patched):
            patched_tag, previous_tag = _release_range(tags, patched_version, package)
            if patched_tag is None or previous_tag is None:
                result.notes.append(f"no tag range found for {package or ''} {patched_version}")
                continue
            source = f"compare {previous_tag}...{patched_tag}"
            try:
                comparison = self._client.compare(repo.owner, repo.name, previous_tag, patched_tag)
            except GitHubError as exc:
                result.notes.append(f"{source} failed: {exc}")
                continue
            for commit in comparison.get("commits", []):
                title = _title(commit["commit"]["message"])
                candidates.setdefault(
                    commit["sha"], Candidate(sha=commit["sha"], title=title, source=source)
                )
            if comparison.get("total_commits", 0) > len(comparison.get("commits", [])):
                result.notes.append(f"{source} has more commits than the API returns; truncated")

        return _rank_candidates(list(candidates.values()), advisory)[:_MAX_CANDIDATES]

    # --- Helpers --------------------------------------------------------------------------------

    def _commit_finding(
        self, repo: RepoRef, sha: str, confidence: Confidence, evidence: str, notes: list[str]
    ) -> CommitFinding | None:
        """Validate a SHA against the repo and build a finding, or return None if it's unknown."""
        try:
            commit = self._client.get_commit(repo.owner, repo.name, sha)
        except GitHubNotFoundError:
            notes.append(f"commit {sha} not found in {repo.full_name}")
            return None
        full_sha = commit["sha"]
        return CommitFinding(
            sha=full_sha,
            commit_url=f"{repo.url}/commit/{full_sha}",
            title=_title(commit["commit"]["message"]),
            committed_at=commit["commit"]["committer"]["date"],
            confidence=confidence,
            evidence=[evidence],
        )

    def _attach_pr(
        self, repo: RepoRef, finding: CommitFinding, linked_prs: dict[int, dict[str, Any]]
    ) -> None:
        """Find the merged PR that contains this commit, preferring PRs the advisory links."""
        assert finding.sha is not None
        try:
            pulls = self._client.get_commit_pulls(repo.owner, repo.name, finding.sha)
        except GitHubError as exc:
            finding.evidence.append(f"could not look up PRs: {exc}")
            return
        merged = [p for p in pulls if p.get("merged_at")]
        chosen = (
            next((p for p in merged if p["number"] in linked_prs), None)
            or next((p for p in merged if p.get("merge_commit_sha") == finding.sha), None)
            or (merged[0] if merged else None)
        )
        if chosen is None:
            if _PRIVATE_FORK_MERGE_RE.match(finding.title):
                finding.evidence.append(
                    "merged from GitHub's temporary private security fork; that PR is deleted "
                    "after publication, so there is no public PR"
                )
            else:
                finding.evidence.append("no merged PR contains this commit (pushed directly)")
            return
        _set_pr(finding, chosen)
        how = "linked in the advisory and " if chosen["number"] in linked_prs else ""
        finding.evidence.append(
            f"PR #{chosen['number']} is {how}listed by GitHub as containing this commit"
        )

    def _default_branch(self, repo: RepoRef, notes: list[str]) -> str | None:
        try:
            return str(self._client.get_repo(repo.owner, repo.name)["default_branch"])
        except GitHubError as exc:
            notes.append(f"could not read the default branch: {exc}")
            return None

    def _on_branch(self, repo: RepoRef, sha: str | None, branch: str | None) -> bool | None:
        """True if the commit is in the branch's history."""
        if sha is None or branch is None:
            return None
        try:
            return self._client.is_ancestor(repo.owner, repo.name, sha, branch)
        except GitHubError:
            return None


def _set_pr(finding: CommitFinding, pr: dict[str, Any]) -> None:
    finding.pr_number = pr["number"]
    finding.pr_url = pr.get("html_url")


def _title(message: str) -> str:
    return message.splitlines()[0].strip() if message else ""


def _commit_sort_key(finding: CommitFinding) -> tuple[bool, str]:
    # Default-branch commits first, then oldest first.
    return (finding.on_default_branch is not True, str(finding.committed_at or ""))


def _choose_primary(commits: list[CommitFinding], advisory: Advisory) -> CommitFinding:
    """Among the fix commits on the default branch (or all, if none is), the one whose title best
    matches the advisory; ties go to the earliest. `commits` is sorted default-branch first, then
    oldest first, and max() keeps the first of equal scores."""
    pool = [c for c in commits if c.on_default_branch] or commits
    words = _advisory_words(advisory)
    best = max(pool, key=lambda c: _relevance(c.title, words))
    primary = best.model_copy(deep=True)
    where = "on the default branch" if primary.on_default_branch else "(none on the default branch)"
    how = "best title match with the advisory" if len(pool) > 1 else "only fix commit"
    others = len(commits) - 1
    primary.reasoning = f"{how} {where}" + (
        f"; {others} more fix commit(s) listed under commits" if others else ""
    )
    return primary


def _keywords(text: str) -> set[str]:
    return {w for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS}


def _advisory_words(advisory: Advisory) -> set[str]:
    # The repo's own name and merge boilerplate ("Merge pull request #1 from org/branch") match
    # almost every advisory, so they don't count.
    noise = _keywords(f"{advisory.repo.owner} {advisory.repo.name} merge pull request branch")
    return _keywords(f"{advisory.summary} {advisory.description}") - noise


def _relevance(title: str, advisory_words: set[str]) -> int:
    """How much a commit title looks like it is about this advisory."""
    shared = len(_keywords(title) & advisory_words)
    return 2 * shared + (1 if _SECURITY_HINT_RE.search(title) else 0)


def _rank_candidates(candidates: list[Candidate], advisory: Advisory) -> list[Candidate]:
    """Most relevant first. Cheap and deterministic; the agent does the real judging."""
    words = _advisory_words(advisory)
    # sorted() is stable, so ties keep commit order.
    return sorted(candidates, key=lambda c: _relevance(c.title, words), reverse=True)


def _tag_version(tag: str, package: str | None) -> Version | None:
    name = tag
    if package and name.lower().startswith(package.lower()):
        name = name[len(package) :].lstrip("-_=@/")
    for prefix in _TAG_PREFIXES:
        if name.lower().startswith(prefix):
            name = name[len(prefix) :]
            break
    try:
        return Version(name)
    except InvalidVersion:
        return None


def _release_range(
    tags: list[str], patched: str, package: str | None
) -> tuple[str | None, str | None]:
    """(tag of the patched version, tag of the closest earlier release) or Nones."""
    try:
        patched_version = Version(patched)
    except InvalidVersion:
        return None, None
    versions = [(v, t) for t in tags if (v := _tag_version(t, package)) is not None]
    patched_tag = next((t for v, t in versions if v == patched_version), None)
    earlier = [
        (v, t)
        for v, t in versions
        if v < patched_version and (patched_version.is_prerelease or not v.is_prerelease)
    ]
    previous_tag = max(earlier)[1] if earlier else None
    return patched_tag, previous_tag
