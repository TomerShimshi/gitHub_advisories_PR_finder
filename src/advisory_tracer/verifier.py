"""Deterministic verification of an introducing-commit answer. Code, not a model, decides
whether the answer holds up, so a confident but wrong model answer is caught."""

from pydantic import BaseModel, Field

from advisory_tracer.diffs import quote_in_added_lines
from advisory_tracer.github_client import GitHubClient, GitHubError
from advisory_tracer.models import Advisory, CommitFinding, Confidence, FixFinding, Verdict


class IntroducedAnswer(BaseModel):
    """The commit that introduced the vulnerability, with checkable reasoning."""

    sha: str | None = Field(description="Full 40-char SHA of the introducing commit, or null.")
    vulnerable_code: str = Field(description="Lines the commit added, quoted from its diff.")
    vulnerable_code_path: str | None = Field(default=None, description="File of that quote.")
    why_vulnerable: str
    why_this_commit: str
    fix_link: str
    confidence: str = Field(description="high, medium or low")


def verify_introduced(
    client: GitHubClient,
    advisory: Advisory,
    fix: FixFinding,
    answer: IntroducedAnswer | None,
    evidence: list[str] | None = None,
) -> CommitFinding:
    """Turn the judge's answer into a finding with a verdict:
    verified  = the commit exists, precedes a fix commit, and the quoted code is in its diff
    plausible = it precedes a fix commit but the quote isn't in its added lines
    rejected  = it doesn't exist or comes after every fix commit"""
    owner, repo = advisory.repo.owner, advisory.repo.name
    finding = CommitFinding(
        evidence=list(evidence or []),
        reasoning="" if answer is None else answer.model_dump_json(),
    )
    if answer is None or not answer.sha:
        finding.verdict_reason = "no introducing commit found"
        return finding
    try:
        commit = client.get_commit(owner, repo, answer.sha)
    except GitHubError:
        finding.verdict, finding.verdict_reason = Verdict.REJECTED, "SHA does not exist"
        return finding

    sha = commit["sha"]
    finding.sha, finding.commit_url = sha, f"{advisory.repo.url}/commit/{sha}"
    finding.title = commit["commit"]["message"].splitlines()[0]
    finding.confidence = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM}.get(
        answer.confidence.lower(), Confidence.LOW
    )
    pulls = [p for p in client.get_commit_pulls(owner, repo, sha) if p.get("merged_at")]
    if pulls:
        finding.pr_number, finding.pr_url = pulls[0]["number"], pulls[0].get("html_url")

    # Release-branch twins precede that branch's backport, not the main fix, so any fix counts.
    fixes = [c.sha for c in fix.commits if c.sha]
    precedes = any(client.is_ancestor(owner, repo, sha, f) for f in fixes) if fixes else True
    files = commit.get("files", [])
    quoted = quote_in_added_lines(
        files, answer.vulnerable_code, answer.vulnerable_code_path
    ) or quote_in_added_lines(files, answer.vulnerable_code)

    if not precedes:
        finding.verdict = Verdict.REJECTED
        finding.verdict_reason = "the commit is not in the history of any fix commit"
    elif quoted:
        finding.verdict = Verdict.VERIFIED
        finding.verdict_reason = "precedes the fix; quoted code is in its added lines"
    else:
        finding.verdict = Verdict.PLAUSIBLE
        finding.verdict_reason = "precedes the fix, but the quoted code is not in its added lines"
    return finding
