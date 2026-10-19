"""Read-only tools the agent uses to investigate one advisory's repository.

Each tool returns plain text sized for a prompt. Errors come back as text ("ERROR: ...") so the
agent can adapt. Every call counts against a per-advisory budget and is recorded as evidence.

SECURITY: the model chooses the arguments, so treat them as untrusted. SHAs must be hex, paths
can't be absolute or contain "..", and every call is pinned to the advisory's own repository.
With more time: an allowlist of paths from the fix diff, and per-tool rate limits.
"""

import inspect
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from typing import Any

from packaging.version import InvalidVersion, Version

from advisory_tracer.diffs import TouchedLine, is_auxiliary, touched_lines
from advisory_tracer.fix_resolver import (
    PRIVATE_FORK_MERGE_RE,
    commit_title,
    next_release_tag,
    rank_candidates,
    release_range,
)
from advisory_tracer.github_client import GitHubClient, GitHubError
from advisory_tracer.models import Advisory, Candidate, FixFinding

log = logging.getLogger(__name__)

_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
# Lower bound of an affected range such as ">= 1.8.0, < 1.30.0" or "> 2.0".
_LOWER_BOUND_RE = re.compile(r"(>=|>)\s*([^,\s]+)")
MAX_DIFF_LINES = 300
MAX_TOUCHED_LINES = 80
MAX_READ_LINES = 150
MAX_BLAME_SPAN = 200
DEFAULT_CALL_BUDGET = 25


class ToolInputError(ValueError):
    """The model passed an argument the tool refuses."""


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    result_summary: str


@dataclass
class BlamedLine:
    line: TouchedLine
    owner: dict[str, Any] | None  # Blame range {sha, date, title, ...}; None if blame failed.

    @property
    def owner_sha(self) -> str | None:
        return self.owner["sha"] if self.owner else None


@dataclass
class LineOwner:
    sha: str
    date: str
    title: str
    removed: int = 0
    context: int = 0


@dataclass
class VulnerableLines:
    sha: str
    parent: str | None
    lines: list[BlamedLine] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def owners(self) -> list[LineOwner]:
        """Commits owning the vulnerable lines before the fix, most removed lines first."""
        owners: dict[str, LineOwner] = {}
        for item in self.lines:
            if not item.owner:
                continue
            o = owners.setdefault(
                item.owner["sha"],
                LineOwner(item.owner["sha"], item.owner["date"], item.owner["title"]),
            )
            if item.line.kind == "removed":
                o.removed += 1
            else:
                o.context += 1
        return sorted(owners.values(), key=lambda o: (o.removed, o.context), reverse=True)


@dataclass
class IntroductionWindow:
    header: str
    commits: list[Candidate]
    total: int


@dataclass
class _Budget:
    limit: int
    used: int = 0
    calls: list[ToolCall] = field(default_factory=list)


def _tool[**P](func: Callable[P, str]) -> Callable[P, str]:
    """Count the call against the budget, log it, and turn failures into text."""

    signature = inspect.signature(func)

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> str:
        self = args[0]
        assert isinstance(self, RepoTools)
        call_args = dict(signature.bind_partial(*args, **kwargs).arguments)
        call_args.pop("self", None)
        if self.budget.used >= self.budget.limit:
            return (
                f"ERROR: tool budget of {self.budget.limit} calls used up. "
                "Answer now with what you have, or report not_found."
            )
        self.budget.used += 1
        try:
            result = func(*args, **kwargs)
        except ToolInputError as exc:
            result = f"ERROR: invalid input: {exc}"
        except GitHubError as exc:
            result = f"ERROR: {exc}"
        self.budget.calls.append(
            ToolCall(func.__name__, call_args, result.splitlines()[0][:200] if result else "")
        )
        log.debug("tool %s(%s) -> %d chars", func.__name__, call_args, len(result))
        return result

    return wrapper


def _check_sha(value: str, name: str = "sha") -> str:
    value = str(value).strip()
    if not _SHA_RE.match(value):
        raise ToolInputError(f"{name} must be a 7-40 character hex commit SHA, got {value!r}")
    return value.lower()


def _check_path(path: str) -> str:
    path = str(path).strip()
    if (
        not path
        or len(path) > 500
        or path.startswith("/")
        or ".." in path.split("/")
        or any(ord(c) < 32 for c in path)
    ):
        raise ToolInputError(f"not a valid repository file path: {path!r}")
    return path


def _check_range(start: int, end: int, max_span: int) -> tuple[int, int]:
    start, end = int(start), int(end)
    if start < 1 or end < start:
        raise ToolInputError(f"bad line range {start}-{end}")
    return start, min(end, start + max_span - 1)


class RepoTools:
    """The agent's tools, bound to one advisory and its repository."""

    def __init__(
        self,
        client: GitHubClient,
        advisory: Advisory,
        fix: FixFinding | None = None,
        *,
        call_budget: int = DEFAULT_CALL_BUDGET,
    ) -> None:
        self._client = client
        self._advisory = advisory
        self._fix = fix or FixFinding()
        self._owner, self._repo = advisory.repo.owner, advisory.repo.name
        self.budget = _Budget(limit=call_budget)

    @property
    def calls(self) -> list[ToolCall]:
        return self.budget.calls

    # --- 1. get_commit_diff ----------------------------------------------------------------------

    @_tool
    def get_commit_diff(self, sha: str, files: list[str] | None = None) -> str:
        """A commit's title, date, parents, changed files and the patches of relevant files.
        Tests, docs, changelogs and lockfiles are listed without patches unless named in
        `files`."""
        commit = self._client.get_commit(self._owner, self._repo, _check_sha(sha))
        if isinstance(files, str):  # Models sometimes pass one path instead of a list.
            files = [files]
        wanted = {_check_path(f) for f in files} if files else None
        out = [
            f"commit {commit['sha']}",
            f"title: {commit_title(commit['commit']['message'])}",
            f"date: {commit['commit']['committer']['date']}",
            f"parents: {', '.join(p['sha'] for p in commit.get('parents', [])) or '(none)'}",
            "files:",
        ]
        for f in commit.get("files", []):
            note = " (auxiliary)" if is_auxiliary(f["filename"]) else ""
            out.append(
                f"  {f['status']:<8} {f['filename']} +{f.get('additions', 0)}"
                f"/-{f.get('deletions', 0)}{note}"
            )
        if len(commit.get("files", [])) >= 300:
            out.append("  (GitHub lists at most 300 files; more may exist)")

        budget = MAX_DIFF_LINES
        for f in commit.get("files", []):
            name = f["filename"]
            if wanted is not None and name not in wanted:
                continue
            if wanted is None and is_auxiliary(name):
                continue
            patch = f.get("patch")
            out.append(f"--- {name}")
            if not patch:
                out.append("  (no patch: binary or too large for the API)")
                continue
            lines = patch.splitlines()
            if len(lines) > budget:
                out.extend(lines[:budget])
                out.append(f"  ... truncated ({len(lines) - budget} more lines in this file)")
                budget = 0
                break
            out.extend(lines)
            budget -= len(lines)
        if budget == 0:
            out.append("... diff output limit reached; ask for specific files with `files`")
        return "\n".join(out)

    # --- 2. get_vulnerable_lines -----------------------------------------------------------------

    @_tool
    def get_vulnerable_lines(self, fix_sha: str) -> str:
        """The pre-fix lines a fix changed, numbered as in the fix's parent, each with the commit
        that last changed it before the fix (blame), plus a per-commit summary."""
        data = self.vulnerable_lines_data(fix_sha)
        out = [f"fix {data.sha}  parent: {data.parent or '(none)'}"]
        if not data.lines:
            out.append(
                "No pre-existing lines touched in non-test files (the fix only adds new files, "
                "or only changes tests/docs). Look at the files it adds and their callers."
            )
            return "\n".join(out)
        current = None
        for item in data.lines[:MAX_TOUCHED_LINES]:
            line = item.line
            if line.path != current:
                current = line.path
                out.append(f"file: {current}")
            marker = "-" if line.kind == "removed" else " "
            owner_sha = item.owner_sha[:12] if item.owner_sha else "?" * 12
            out.append(f"  L{line.old_line:<5} {owner_sha} {marker} {line.text}")
        if len(data.lines) > MAX_TOUCHED_LINES:
            out.append(f"... {len(data.lines) - MAX_TOUCHED_LINES} more lines not shown")
        out.append("('-' = removed by the fix; ' ' = code next to a check the fix added)")
        out.append("last changed before the fix by (lines removed / context):")
        for owner in data.owners():
            out.append(
                f"  {owner.sha}  {owner.date[:10]}  {owner.removed}/{owner.context}  "
                f"{owner.title[:80]}"
            )
        out.extend(f"note: {n}" for n in data.notes)
        return "\n".join(out)

    def vulnerable_lines_data(self, fix_sha: str) -> VulnerableLines:
        """Structured form of get_vulnerable_lines (not counted against the budget)."""
        commit = self._client.get_commit(self._owner, self._repo, _check_sha(fix_sha, "fix_sha"))
        parents = [p["sha"] for p in commit.get("parents", [])]
        # Merge commits (e.g. from a private security fork): GitHub diffs against the first
        # parent, which is also where the pre-fix code lives.
        result = VulnerableLines(sha=commit["sha"], parent=parents[0] if parents else None)
        lines = touched_lines(commit.get("files", []))
        blames: dict[str, list[dict[str, Any]]] = {}
        for path in dict.fromkeys(line.path for line in lines):
            if result.parent is None:
                break
            try:
                blames[path] = self._client.blame(self._owner, self._repo, result.parent, path)
            except GitHubError as exc:
                result.notes.append(f"blame failed for {path}: {exc}")
        for line in lines:
            owner = next(
                (r for r in blames.get(line.path, []) if r["start"] <= line.old_line <= r["end"]),
                None,
            )
            result.lines.append(BlamedLine(line, owner))
        return result

    # --- 3. blame --------------------------------------------------------------------------------

    @_tool
    def blame(self, path: str, ref: str, start_line: int, end_line: int) -> str:
        """Which commit last changed each line of `path` in the range, as of commit `ref`."""
        path, ref = _check_path(path), _check_sha(ref, "ref")
        start, end = _check_range(start_line, end_line, MAX_BLAME_SPAN)
        ranges = self._client.blame(self._owner, self._repo, ref, path)
        out = [f"blame {path} at {ref[:12]}, lines {start}-{end}:"]
        for r in ranges:
            lo, hi = max(r["start"], start), min(r["end"], end)
            if lo > hi:
                continue
            span = f"L{lo}" if lo == hi else f"L{lo}-{hi}"
            out.append(f"  {span:<12} {r['sha']}  {r['date'][:10]}  {r['title'][:90]}")
        if len(out) == 1:
            out.append("  (no lines in that range; the file may be shorter)")
        return "\n".join(out)

    # --- 4. file_history -------------------------------------------------------------------------

    @_tool
    def file_history(self, path: str, ref: str, limit: int = 15) -> str:
        """Commits that touched `path`, newest first, up to and including `ref`."""
        path, ref = _check_path(path), _check_sha(ref, "ref")
        commits = self._client.list_commits(
            self._owner, self._repo, ref=ref, path=path, limit=max(1, min(int(limit), 30))
        )
        if not commits:
            return f"no commits touch {path} as of {ref[:12]} (wrong path, or renamed?)"
        out = [f"history of {path} as of {ref[:12]} (newest first):"]
        out.extend(
            f"  {c['sha']}  {c['commit']['committer']['date'][:10]}  "
            f"{commit_title(c['commit']['message'])[:90]}"
            for c in commits
        )
        return "\n".join(out)

    # --- 5. read_file ----------------------------------------------------------------------------

    @_tool
    def read_file(self, path: str, ref: str, start_line: int = 1, end_line: int = 80) -> str:
        """Lines of `path` at commit `ref`, numbered."""
        path, ref = _check_path(path), _check_sha(ref, "ref")
        start, end = _check_range(start_line, end_line, MAX_READ_LINES)
        text = self._client.get_file_text(self._owner, self._repo, path, ref)
        if text is None:
            return f"ERROR: {path} at {ref[:12]} is binary, a directory, or larger than 1 MB"
        lines = text.splitlines()
        if start > len(lines):
            return f"{path} at {ref[:12]} has only {len(lines)} lines"
        out = [f"{path} at {ref[:12]}, lines {start}-{min(end, len(lines))} of {len(lines)}:"]
        out.extend(f"{n:>6}  {lines[n - 1]}" for n in range(start, min(end, len(lines)) + 1))
        return "\n".join(out)

    # --- 6. find_prs -----------------------------------------------------------------------------

    @_tool
    def find_prs(self, sha: str) -> str:
        """The merged pull request that contains a commit, if any."""
        sha = _check_sha(sha)
        pulls = self._client.get_commit_pulls(self._owner, self._repo, sha)
        merged = [p for p in pulls if p.get("merged_at")]
        if merged:
            return "\n".join(
                f"PR #{p['number']}: {p.get('title', '')} ({p.get('html_url', '')}), "
                f"merged {p['merged_at'][:10]} into {p.get('base', {}).get('ref', '?')}"
                for p in merged[:3]
            )
        commit = self._client.get_commit(self._owner, self._repo, sha)
        if PRIVATE_FORK_MERGE_RE.match(commit_title(commit["commit"]["message"])):
            return "no public PR: merged from GitHub's temporary private security fork"
        return "no merged PR contains this commit (pushed directly)"

    # --- 7. is_ancestor --------------------------------------------------------------------------

    @_tool
    def is_ancestor(self, older_sha: str, newer_sha: str) -> str:
        """Whether `older_sha` is in the history of `newer_sha`."""
        older, newer = _check_sha(older_sha, "older_sha"), _check_sha(newer_sha, "newer_sha")
        yes = self._client.is_ancestor(self._owner, self._repo, older, newer)
        verdict = "is" if yes else "is NOT"
        return f"{older[:12]} {verdict} an ancestor of {newer[:12]}"

    # --- 9. introduction_window ------------------------------------------------------------------

    @_tool
    def introduction_window(self, limit: int = 30) -> str:
        """Commits between the last unaffected and the first affected release, from the lower
        bound of the advisory's affected version range."""
        limit = max(1, min(int(limit), 50))
        windows = self.introduction_windows()
        if not windows:
            return (
                "no lower bound in the affected version ranges: all versions are affected, so "
                "the vulnerable code likely predates the first release. Rely on blame/history."
            )
        out: list[str] = []
        for window in windows:
            out.append(window.header)
            out.extend(f"  {c.sha}  {c.title[:90]}" for c in window.commits[:limit])
            if window.total > len(window.commits[:limit]):
                out.append(f"  ... {window.total - len(window.commits[:limit])} more not shown")
        return "\n".join(out)

    def introduction_windows(self) -> list[IntroductionWindow]:
        """Structured form of introduction_window (not counted against the budget).

        Only each package's lowest lower bound marks an introduction: a range like
        ">= 2.0.0, < 2.2.0" starts a new major line that inherited the bug. A package with any
        unbounded range ("< 1.26.17") is affected in all versions and gets no window."""
        bounds = _lowest_lower_bounds(self._advisory)
        if not bounds:
            return []
        tags = self._client.list_tags(self._owner, self._repo)
        windows: list[IntroductionWindow] = []
        for package, (operator, version) in bounds.items():
            if operator == ">=":
                first_affected, last_unaffected = release_range(tags, version, package)
            else:  # "> X": X itself is unaffected.
                last_unaffected = release_range(tags, version, package)[0]
                first_affected = next_release_tag(tags, version, package)
            label = f"{package or ''} {operator} {version}".strip()
            if not first_affected or not last_unaffected:
                windows.append(IntroductionWindow(f"{label}: no matching release tags", [], 0))
                continue
            comparison = self._client.compare(
                self._owner, self._repo, last_unaffected, first_affected, max_commits=300
            )
            commits = rank_candidates(
                [
                    Candidate(
                        sha=c["sha"],
                        title=commit_title(c["commit"]["message"]),
                        source=f"{last_unaffected}...{first_affected}",
                    )
                    for c in comparison.get("commits", [])
                ],
                self._advisory,
            )
            total = int(comparison.get("total_commits", len(commits)))
            header = (
                f"{label}: introduced between {last_unaffected} (unaffected) and "
                f"{first_affected} (first affected), {total} commits, most relevant first:"
            )
            windows.append(IntroductionWindow(header, commits, total))
        return windows

    # --- 8. list_candidates ----------------------------------------------------------------------

    @_tool
    def list_candidates(self, limit: int = 20) -> str:
        """Possible fix commits when the advisory doesn't link one: release-range candidates
        from the resolver, else commits from the 30 days before the advisory was published."""
        candidates = self.fix_candidates(max(1, min(int(limit), 50)))
        if not candidates:
            return "no candidate fix commits found"
        out = ["possible fix commits (most relevant first):"]
        out.extend(f"  {c.sha}  {c.title[:90]}  [{c.source}]" for c in candidates)
        return "\n".join(out)

    def fix_candidates(self, limit: int = 20) -> list[Candidate]:
        if self._fix.candidates:
            return self._fix.candidates[:limit]
        published = self._advisory.published_at
        if published is None:
            return []
        branch = self._client.get_repo(self._owner, self._repo)["default_branch"]
        since = published - timedelta(days=30)
        commits = self._client.list_commits(
            self._owner,
            self._repo,
            ref=branch,
            since=_iso(since),
            until=_iso(published),
            limit=limit,
        )
        return [
            Candidate(
                sha=c["sha"],
                title=commit_title(c["commit"]["message"]),
                source="30 days before publication",
            )
            for c in commits
        ]


def _lowest_lower_bounds(advisory: Advisory) -> dict[str | None, tuple[str, str]]:
    """Per package, the (operator, version) of its lowest lower bound; packages with an
    unbounded range are left out."""
    ranges: dict[str | None, list[str]] = {}
    for v in advisory.vulnerabilities:
        if v.vulnerable_version_range:
            ranges.setdefault(v.package, []).append(v.vulnerable_version_range)
    result: dict[str | None, tuple[str, str]] = {}
    for package, specs in ranges.items():
        found = [m for spec in specs if (m := _LOWER_BOUND_RE.search(spec))]
        if len(found) < len(specs):
            continue  # Some range has no lower bound: every version is affected.
        try:
            lowest = min(found, key=lambda m: Version(m[2]))
        except InvalidVersion:
            continue
        result[package] = (lowest[1], lowest[2])
    return result


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
