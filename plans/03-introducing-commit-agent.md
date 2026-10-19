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
_Update after Plan 2._

## Results
_Fill in when done: accuracy on the ground-truth set, cost per advisory, model choices, clone decision._
