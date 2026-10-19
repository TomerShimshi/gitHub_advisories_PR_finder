# Plan 3: LLM client, cost tracking, introducing-commit agent

**Status:** Not started
**Uses LLM:** Yes (first plan that spends money)

## Goal
Given a known fix commit, find the commit (and PR) that introduced the vulnerability, while keeping cost per advisory low and capped. This is the riskiest plan; its results may reshape Plans 4 and 5.

## Deliverable
- **OpenRouter client:** OpenAI-compatible, used through LangChain's `ChatOpenAI` with OpenRouter's base URL and the key from the environment.
- **Two model tiers:** a cheap DeepSeek model for mechanical steps; one stronger but cost-effective reasoning model for the hard judgement. Exact model IDs and prices checked on OpenRouter at the start of this plan and recorded here.
- **Cost tracking:** tokens and dollars per call, per advisory, and per run. A hard budget cap that stops the run cleanly and still writes partial results.
- **LLM response cache:** identical prompts are never paid for twice.
- **Introducing-commit agent (LangGraph):**
  1. Take the fix diff and identify the vulnerable lines (lines the fix removed or changed).
  2. Run GraphQL `blame` on the fix commit's parent for those lines to get candidate commits.
  3. If a candidate only reformatted or moved code, walk back with file history (`GET /commits?path=...`).
  4. The model judges which candidate actually introduced the flaw, using small diff snippets, not whole files.
  5. Map the chosen commit to its PR.
  - Returns the commit, PR, evidence, confidence, and reasoning, or `not_found` with a reason.
- **Clone fallback:** only if the API proves insufficient on the test set (code moved across files, blame timeouts). Blobless, no checkout, no submodules, LFS skipped, `core.symlinks=false`, temp dir, nothing executed.

## Definition of Done
- [ ] On the Plan 2 ground-truth set, each advisory gets an introducing commit with evidence, or `not_found` with a reason.
- [ ] Every returned introducing commit exists and is an ancestor of the fix commit (checked through the API).
- [ ] Cost per advisory is logged, and the total for the ground-truth set is recorded in **Results**.
- [ ] Setting the budget cap below the expected cost stops the run cleanly with partial results saved.
- [ ] A second run of the same set costs $0 (LLM cache hits).
- [ ] Decision recorded: is the clone fallback needed? (yes/no, with evidence)

## Security notes to leave in the code
- Prompt injection: diffs, commit messages, and advisory text are untrusted. Agents only get read-only tools; with more time, add input sanitising and output schema enforcement.
- Clone fallback (if built): see the safeguards above.

## Risks
- The vulnerability may be an omission (a missing check) rather than added lines: blame on removed lines finds nothing. The agent must handle "fix only adds lines" by blaming the surrounding code.
- The "introducing" commit is sometimes the file's first commit: that is a valid answer if justified.
- Squash-merged PRs: the commit-to-PR mapping still works but the PR may hold several changes.

## Changes from earlier plans
From Plan 2 (see its Results):
- **Start from every default-branch fix commit, not just the primary.** Multi-part fixes are common (CairoSVG: 2 independent bugs; pydantic-ai: 3 commits on main). Backports on release branches show the same change again, so skip them for blame. If no fix commit is on the default branch (langflow), use the one the fix was merged into.
- **Private security fork merges** ("Merge pull request from GHSA-...") are merge commits. Take the diff against the first parent and blame on the first parent.
- **New first step for deferred advisories:** when the resolver found no fix (`fix.candidates` set, like wger), the agent must first pick the fix commit(s) from the ranked candidates. Use the cheap model, and fetch the diffs of only the top few candidates. Score it with the ground truth's `candidate_rank` and `deferred` outcome.
- **Candidates for the 7% with none:** monorepo sub-packages with no version tags (PraisonAI) and advisories with no patched version (pyload). Add a date-window fallback: commits in the ~30 days before `published_at`, ranked the same way.
- **Diffs are large.** A single commit payload can be 1 MB (langflow backports). Send the model only the hunks for relevant files, and trim the rest. This is the main cost lever.
- **The ground truth needs introducing commits.** Extend `data/ground_truth.yaml` with an `introduced` section (commit, PR, how verified) for the same 10 advisories before measuring.
- The search API allows 30 requests per minute, and the client already waits it out. GraphQL blame has its own point budget, so watch it.

## Results
_Fill in when done: accuracy on the ground-truth set, cost per advisory, model choices, clone decision._
