from advisory_tracer.evaluate import FixTruth, TruthCommit, TruthEntry, score_fix
from advisory_tracer.models import Candidate, CommitFinding, FixFinding

A, B, C = "a" * 40, "b" * 40, "c" * 40


def _truth(primary: str | None, commits: list[tuple[str, int | None]], **kw: object) -> TruthEntry:
    return TruthEntry(
        ghsa_id="GHSA-x",
        repo="o/r",
        fix=FixTruth(
            primary=primary,
            commits=[TruthCommit(sha=s, pr=p) for s, p in commits],
            **kw,  # type: ignore[arg-type]
        ),
    )


def _finding(
    primary: str | None, pr: int | None = None, others: tuple[str, ...] = ()
) -> FixFinding:
    p = CommitFinding(sha=primary, pr_number=pr)
    commits = [p, *(CommitFinding(sha=s) for s in others)] if primary else []
    return FixFinding(primary=p, commits=commits)


def test_correct_with_pr() -> None:
    score = score_fix(_truth(A, [(A, 5), (B, None)]), _finding(A, 5, (B,)))

    assert score.outcome == "correct"
    assert score.primary_exact and score.pr_correct and score.ok
    assert (score.commits_found, score.commits_expected, score.unexpected_commits) == (2, 2, 0)


def test_valid_but_not_primary_commit_is_correct_not_exact() -> None:
    score = score_fix(_truth(A, [(A, None), (B, 7)]), _finding(B, 7))

    assert score.outcome == "correct"
    assert not score.primary_exact
    assert score.pr_correct  # The PR is judged against the commit that was chosen.


def test_also_primary_counts_as_exact() -> None:
    score = score_fix(_truth(A, [(A, None), (B, None)], also_primary=[B]), _finding(B))

    assert score.primary_exact


def test_wrong_commit_and_wrong_pr() -> None:
    score = score_fix(_truth(A, [(A, 5)]), _finding(C, 5))

    assert score.outcome == "wrong"
    assert not score.ok
    assert not score.pr_correct


def test_unlinked_fix_deferred_when_in_candidates() -> None:
    finding = FixFinding(candidates=[Candidate(sha=C), Candidate(sha=B)])

    score = score_fix(_truth(A, [(A, None), (B, None)], linked=False), finding)

    assert score.outcome == "deferred"
    assert score.candidate_rank == 2
    assert score.ok


def test_unlinked_fix_lost_when_not_in_candidates() -> None:
    score = score_fix(_truth(A, [(A, None)], linked=False), FixFinding())

    assert score.outcome == "deferred_lost"
    assert not score.ok


def test_linked_fix_not_found_is_missed() -> None:
    assert score_fix(_truth(A, [(A, None)]), FixFinding()).outcome == "missed"


def test_no_known_fix() -> None:
    assert score_fix(_truth(None, []), FixFinding()).outcome == "honest_not_found"
    assert score_fix(_truth(None, []), _finding(A)).outcome == "false_positive"
