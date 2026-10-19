# Plan 2: Deterministic fix-side resolver

**Status:** Done (2026-10-19), not committed yet
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
- [x] `docker compose run --rm tracer resolve-fix --ids <ground-truth IDs>` prints the fix commit and PR for each.
- [x] Every advisory with a linked fix commit or PR is resolved correctly against the ground truth (9/9).
- [x] Advisories with no link return `not_found` with a reason, and their candidate commit lists are saved (wger: real fix ranked 1st of 371).
- [x] No resolved SHA fails validation (every SHA is fetched from the repo before it is reported).
- [x] LLM spend: $0 (no LLM client exists yet).
- [x] Unit tests cover reference parsing (commit, PR, compare, and malformed URLs).

## Security notes to leave in the code
- Advisory references are untrusted input: only accept URLs that match the expected GitHub pattern for the advisory's own repo.

## Risks
- Tag names do not always match version strings (`v1.2.3` vs `1.2.3` vs `release-1.2.3`): need tag matching logic.
- A fix can span several commits or a PR: the schema may need to allow a list.

## Changes from earlier plans
From Plan 1 (see its Results):
- **Multiple fix commits are common**: an advisory can link one commit per release branch (e.g. GHSA-jwrc-gm9j-263p has 3). Change the schema so the fix side holds a list of commits and PRs, and mark one as primary (e.g. the one on the default branch, or the earliest) for Plan 3 to work from.
- **Don't infer the language from the ecosystem.** A `pip` advisory can have its fix in TypeScript.
- Use the repository advisory link (`/security/advisories/GHSA-...`) and release tag links in the references as extra signals.
- Reuse `GitHubClient._get` (caching, retries) by adding public methods for commits, commit-to-PR and compare. Commit data is immutable, so cache it with no TTL.
- Build the ground-truth set from real advisories and save the recorded API responses as test fixtures.

## Results
**Commands:** `tracer resolve-fix` writes `output/fix_results.yaml`; `tracer eval-fix` scores against `data/ground_truth.yaml`.

**Ground truth (10 advisories, `eval-fix`):**

| Metric | Result |
|---|---|
| Fix commit correct (or correctly deferred) | 10/10 |
| Primary commit exactly as hand-picked | 9/10 (the 10th is wger, deferred to the agent) |
| Fix PR correct | 10/10 |
| All fix commits found (backports, multi-part) | 20/20 for the 9 linked advisories |
| Extra commits that aren't fixes | 0 |
| API calls, cold cache | 96 (cached rerun: 0) |
| LLM cost | $0 |

**100 newest PyPI advisories (`resolve-fix --limit 100`):** 78 fix commits found (77 high confidence, 1 from GHSA search), 15 deferred with candidates, 7 with no candidates, 0 errors. 441 API calls; the search API's 30/minute limit was hit 3 times and handled by waiting.

**How it works:** linked commits and PRs, then search for the GHSA/CVE ID, then the release range (`compare previous_tag...patched_tag`) as ranked candidates. The primary is the default-branch fix commit whose title best matches the advisory; ties go to the earliest.

**Findings that changed the design:**
- **Private security fork merges are common.** Titles like "Merge pull request from GHSA-..." or "Merge commit from fork" come from GitHub's temporary private fork, whose PR is deleted after publication. "No PR" is the correct answer there, and the evidence says so.
- **Fixes land on non-default branches.** langflow merged its fix into a `security-hardening` branch; neither fix commit is in `main`. The tool reports that rather than forcing a default-branch answer.
- **"Earliest commit" was the wrong primary rule.** CairoSVG's advisory names two independent O(n²) bugs, one per commit. My first ground truth was also wrong: it called the second commit a "supporting change". The ground truth now allows alternative primaries (`also_primary`) for fixes in several equal parts.
- **The compare API is very expensive by default.** It always returns the full diff (2.6 to 3.7 MB per call). The fix: check ancestry as `branch...commit`, where the diff is empty when the answer is yes, and trim responses before caching. The cache went from 65 MB to 4 MB.
- **Candidate ranking:** word overlap between commit titles and the advisory text, ignoring the repo name and merge boilerplate. For wger the real fix ranks 1st of 371; the other two parts rank 35th and 36th.

**Not done, on purpose:** recorded real API responses as unit-test fixtures. The commit payloads are up to 1 MB each, too big for the repo. The unit tests use small mocked responses (63 tests), and `eval-fix` is the real-data regression check.

**Known gaps (handed to Plan 3):**
- 6/100 are monorepo sub-packages (e.g. `praisonaiagents` in PraisonAI) whose versions have no tags, and 1/100 has no patched version. They get no candidates.
- Fixes with no link and no ID in the commit message (like wger) need the agent to pick from candidates.
