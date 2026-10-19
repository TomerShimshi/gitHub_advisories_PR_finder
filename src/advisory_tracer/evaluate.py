"""Score results against a hand-checked ground-truth file (data/ground_truth.yaml)."""

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from advisory_tracer.models import FixFinding


class TruthCommit(BaseModel):
    sha: str
    pr: int | None = None  # The public PR that merged this commit; None if there is none.
    # Links for checking the entry by hand; not used for scoring.
    url: str | None = None
    pr_url: str | None = None


class FixTruth(BaseModel):
    primary: str | None = None  # None means no fix commit is known (expect "not found").
    # Other commits that are equally valid as "the" fix (e.g. a fix in two independent parts).
    also_primary: list[str] = Field(default_factory=list)
    commits: list[TruthCommit] = Field(default_factory=list)  # Every accepted fix commit.
    # False when the advisory doesn't link or mention the fix: the resolver can't confirm it and
    # should hand over candidates instead (the agent's job from Plan 3).
    linked: bool = True


class IntroductionReasoning(BaseModel):
    """Why a commit introduced the vulnerability (the same fields the agent must fill in)."""

    vulnerable_code: str  # Lines the introducing commit added, quoted from its diff.
    vulnerable_code_path: str | None = None  # File the quote is from, as named in that commit.
    why_vulnerable: str
    why_this_commit: str
    fix_link: str
    confidence: str = "high"


class IntroducedTruth(BaseModel):
    primary: str | None = None
    also_primary: list[str] = Field(default_factory=list)
    # Every commit accepted as introducing (e.g. the same flaw copied into several views).
    commits: list[TruthCommit] = Field(default_factory=list)
    reasoning: IntroductionReasoning | None = None


class TruthEntry(BaseModel):
    ghsa_id: str
    repo: str
    advisory_url: str | None = None
    fix: FixTruth
    introduced: IntroducedTruth | None = None
    how_verified: str = ""


def load_ground_truth(path: Path) -> list[TruthEntry]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [TruthEntry.model_validate(item) for item in raw]


@dataclass
class FixScore:
    ghsa_id: str
    # correct | wrong | missed | false_positive | honest_not_found
    # | deferred (unlinked fix, real fix is among the candidates) | deferred_lost (it isn't)
    outcome: str
    primary_exact: bool
    pr_correct: bool
    commits_found: int
    commits_expected: int
    unexpected_commits: int
    candidate_rank: int | None  # 1-based rank of the best real fix commit among candidates.

    @property
    def ok(self) -> bool:
        return self.outcome in ("correct", "honest_not_found", "deferred")


def score_fix(truth: TruthEntry, finding: FixFinding) -> FixScore:
    pr_of = {c.sha.lower(): c.pr for c in truth.fix.commits}
    expected = set(pr_of)
    found = {c.sha for c in finding.commits if c.sha}
    primary = finding.primary.sha
    ranks = [i for i, c in enumerate(finding.candidates, 1) if c.sha.lower() in expected]
    candidate_rank = min(ranks) if ranks else None

    if not expected:
        outcome = "honest_not_found" if primary is None else "false_positive"
    elif primary is None and not truth.fix.linked:
        outcome = "deferred" if candidate_rank else "deferred_lost"
    elif primary is None:
        outcome = "missed"
    else:
        outcome = "correct" if primary in expected else "wrong"

    # The PR is judged for whichever commit was chosen, as long as that commit is a real fix.
    pr_correct = primary is not None and primary in pr_of and finding.primary.pr_number == pr_of[
        primary
    ]
    if not expected or primary is None:
        pr_correct = finding.primary.pr_number is None
    return FixScore(
        ghsa_id=truth.ghsa_id,
        outcome=outcome,
        primary_exact=(
            primary in {s.lower() for s in [truth.fix.primary, *truth.fix.also_primary] if s}
            if primary
            else truth.fix.primary is None
        ),
        pr_correct=pr_correct,
        commits_found=len(found & expected),
        commits_expected=len(expected),
        unexpected_commits=len(found - expected),
        candidate_rank=candidate_rank,
    )


def format_table(scores: list[FixScore]) -> str:
    header = (
        f"{'advisory':<22}{'outcome':<18}{'exact':<7}{'pr':<6}{'commits':<10}{'extra':<7}"
        f"{'cand.rank':<9}"
    )
    lines = [header, "-" * len(header)]
    for s in scores:
        lines.append(
            f"{s.ghsa_id:<22}{s.outcome:<18}{_yn(s.primary_exact):<7}{_yn(s.pr_correct):<6}"
            f"{f'{s.commits_found}/{s.commits_expected}':<10}{s.unexpected_commits:<7}"
            f"{s.candidate_rank or '-'!s:<9}"
        )
    ok = sum(s.ok for s in scores)
    exact = sum(s.primary_exact for s in scores)
    prs = sum(s.pr_correct for s in scores)
    lines.append("-" * len(header))
    lines.append(
        f"fix commit ok: {ok}/{len(scores)}   primary exact: {exact}/{len(scores)}   "
        f"fix PR ok: {prs}/{len(scores)}"
    )
    return "\n".join(lines)


def _yn(value: bool) -> str:
    return "yes" if value else "NO"
