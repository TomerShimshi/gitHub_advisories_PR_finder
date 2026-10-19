# Plan 2: Deterministic fix-side resolver

**Status:** Not started
**Uses LLM:** No

## Goal
Find the fix commit and the fix PR for an advisory using only the GitHub API, with no LLM spend. This proves the cheap, reliable part before any money is spent.

## Deliverable
- **Candidate extraction:** parse advisory references for commit URLs, PR URLs, and compare URLs.
- **Validation:** confirm every candidate SHA exists in the advisory's repo (`GET /repos/{owner}/{repo}/commits/{sha}`).
- **PR mapping:** commit to PR via `GET /repos/{owner}/{repo}/commits/{sha}/pulls`; PR to its commits via `GET /repos/{owner}/{repo}/pulls/{n}/commits`.
- **Fallback when nothing is linked:** `compare/{last_vulnerable_tag}...{first_patched_tag}` to list candidate commits, stored for Plan 3 to rank (no guessing here).
- **Selection:** pick the fix commit and PR, with a confidence level (`high` for a linked and validated commit, `medium` for a linked PR whose merge commit is used, `none` when unresolved) and the evidence (URLs, API results).
- **Ground-truth set:** about 10 hand-picked PyPI advisories with known fix commits and PRs, stored as a fixture file. Reused by later plans.

## Definition of Done
- [ ] `docker compose run --rm tracer resolve-fix --ids <ground-truth IDs>` prints the fix commit and PR for each.
- [ ] Every advisory with a linked fix commit or PR is resolved correctly against the ground truth.
- [ ] Advisories with no link return `not_found` with a reason, and their candidate commit lists are saved.
- [ ] No resolved SHA fails validation.
- [ ] LLM spend: $0 (no LLM client exists yet).
- [ ] Unit tests cover reference parsing (commit, PR, compare, and malformed URLs).

## Security notes to leave in the code
- Advisory references are untrusted input: only accept URLs that match the expected GitHub pattern for the advisory's own repo.

## Risks
- Tag names do not always match version strings (`v1.2.3` vs `1.2.3` vs `release-1.2.3`): need tag matching logic.
- A fix can span several commits or a PR: the schema may need to allow a list.

## Changes from earlier plans
_Update after Plan 1._

## Results
_Fill in when done._
