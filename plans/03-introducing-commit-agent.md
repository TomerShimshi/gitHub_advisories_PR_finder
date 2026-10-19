# Plan 3: LLM client, cost tracking, introducing-commit agent

**Status:** Done with known gaps (see Results)
**Uses LLM:** Yes (first plan that spends money)

## Goal
Given a known fix commit, find the commit (and PR) that introduced the vulnerability, while keeping cost per advisory low and capped. This is the riskiest plan; its results may reshape Plans 4 and 5.

## Deliverable
- **OpenRouter client:** OpenAI-compatible, used through LangChain's `ChatOpenAI` with OpenRouter's base URL and the key from the environment.
- **Two model tiers (decided 2026-10-19, OpenRouter prices per 1M tokens in/out):**
  - **Investigator: `deepseek/deepseek-v4.1-flash`** ($0.033 / $0.08). Runs the tool-calling loop (the heavy lifting: many calls, large inputs) and returns an evidence dossier.
  - **Judge: `anthropic/claude-opus-5.5`** ($4 / $20). Called once per advisory on the compact dossier (no raw diffs). Picks the introducing commit and writes the reasoning fields. Estimated ~$0.06 per advisory.
  - If Opus turns out to be overkill, Plan 5 compares cheaper judges (e.g. `deepseek/deepseek-v4-pro` at $0.43 / $0.86) on the ground truth. Pinned model versions, never `~latest` aliases.
  - The Plan 4 verifier must use a third model family (neither DeepSeek nor Claude), so it doesn't share their blind spots.
- **Cost tracking:** tokens and dollars per call, per advisory, and per run. A hard budget cap that stops the run cleanly and still writes partial results.
- **LLM response cache:** identical prompts are never paid for twice.
- **Introducing-commit agent (LangGraph):**
  1. Take the fix diff and identify the vulnerable lines (lines the fix removed or changed).
  2. Run GraphQL `blame` on the fix commit's parent for those lines to get candidate commits.
  3. If a candidate only reformatted or moved code, walk back with file history (`GET /commits?path=...`).
  4. The model judges which candidate actually introduced the flaw, using small diff snippets, not whole files.
  5. Map the chosen commit to its PR.
  - Returns the commit, PR, evidence, confidence, and a structured reasoning (below), or `not_found` with a reason.

## Introducing-commit reasoning (required for every answer)

Every introducing commit the agent reports must explain **why** it introduced the vulnerability, in fixed fields that the verifier (Plan 4) and a person can check one by one. An answer without them is rejected and retried, or reported as `not_found`.

| Field | What it must contain | Example (wger) |
|---|---|---|
| `vulnerable_code` | The exact lines this commit added or changed that the fix later removed or guarded, with file and line numbers. Quoted from the diff, not paraphrased. | `wger/gym/views/admin_notes.py:75  if user.userprofile.gym_id != request.user.userprofile.gym_id:` |
| `why_vulnerable` | How that code causes the flaw described in the advisory (link to the summary and CWE). | `None != None` is False, so a trainer with no gym passes the guard (CWE-863). |
| `why_this_commit` | Why this is the origin and not a later edit: what the code looked like before this commit, and the blame/history steps that led here. | Before this commit the view had no gym check at all; blame on the fix's parent points here and no later commit changed the line. |
| `fix_link` | How the fix undoes it: which fix lines replace or guard `vulnerable_code`. | Fix `b51f472` replaces this exact comparison with `is_same_gym()`. |
| `evidence` | The tool calls behind each claim (blame ranges, diffs read, ancestor check result). | `blame(admin_notes.py, parent of b51f472, 70-80)` → `<sha>` |
| `confidence` | high / medium / low, with what would raise it. | |

**Rules:**
- Quotes in `vulnerable_code` must appear in that commit's diff. The verifier checks this deterministically; a made-up quote means the answer is rejected.
- If the flaw is a **missing check** (the fix only adds lines), `vulnerable_code` is the unguarded code the commit introduced, and `why_vulnerable` names the check it lacked.
- If the code passed through several commits (written, then moved or reformatted), `why_this_commit` lists the chain and explains why the earliest is the introducing one.
- The **ground truth** entries get the same fields, written by hand, so the agent's reasoning can be compared with them, not just its SHA.
- **Clone fallback:** only if the API proves insufficient on the test set (code moved across files, blame timeouts). Blobless, no checkout, no submodules, LFS skipped, `core.symlinks=false`, temp dir, nothing executed.

## Agent tools (approved)

The tools the agent can call while investigating. All are **read-only**, work only on the advisory's own repo, and run through the cached, rate-limited `GitHubClient`. They are built and tested before any LLM is wired in, so that step costs $0.

| # | Tool | Input | Returns | Size cap | Backed by |
|---|------|-------|---------|----------|-----------|
| 1 | `get_commit_diff` | sha, optional file filter | Title, date, parents, changed-file list (+/− counts) and the patch hunks of relevant files. Tests, docs, lockfiles and changelogs are listed but their patches skipped. | ~300 diff lines; truncation is marked | REST `commits/{sha}` |
| 2 | `get_vulnerable_lines` | fix sha | Per file: the lines the fix removed or changed, with line numbers in the **parent** (pre-fix) version. For hunks that only add lines (a missing check), the surrounding context lines instead; hunks adding only imports are ignored. Merge commits are diffed against the first parent. **Changed during build:** each line also shows the commit that last changed it before the fix (blame on the parent), plus a per-commit summary, because that is deterministic and saves the agent several paid round-trips. | ~80 lines | Tool 1 + one GraphQL blame per file |
| 3 | `blame` | path, ref, line range | For each line range: last commit SHA, date, title. | Requested range only | **GraphQL** `blame` (REST has none) |
| 4 | `file_history` | path, ref, limit | Commits touching the file before `ref`, newest first (SHA, date, title). Used when blame lands on a reformat or rename. | 30 commits | REST `commits?sha=&path=` |
| 5 | `read_file` | path, ref, line range | Those lines of the file at that commit, numbered. | ~150 lines | REST `contents` |
| 6 | `find_prs` | sha | The merged PR containing the commit (number, title, URL), or none. Private-fork merges are explained. | 1 PR | REST `commits/{sha}/pulls` (exists) |
| 7 | `is_ancestor` | sha_a, sha_b | Whether a comes before b in history. The agent must check it for every proposed introducing commit. | yes/no | REST compare (exists) |
| 9 | `introduction_window` | — | **Added 2026-10-19 (approved).** From the advisory's affected range lower bound (e.g. `>= 0.3.4`): the commits between the last unaffected and the first affected release, ranked by relevance. If there is no lower bound (all versions affected), says so: the origin predates the first release. | top 30 | REST tags + compare |
| 8 | `list_candidates` | — | For deferred advisories only: the ranked fix candidates from Plan 2, plus a date-window fallback (commits in the ~30 days before `published_at`). | top 20 | Plan 2 output, REST commits |

**Rules for every tool:**
- **Validated inputs.** SHAs must be hex and paths are URL-encoded, so the model can't inject URLs or reach other repos.
- **Errors come back as text** (e.g. "file not found at that commit"), not exceptions, so the agent can adapt instead of crashing.
- **Per-advisory call budget**, e.g. 25 tool calls. When it runs out, the agent must answer with what it has, or `not_found`.
- **Every tool call is logged** to the advisory's evidence trail, so the verifier (Plan 4) can see how the answer was reached.

**Not included:** code search through history (git pickaxe `-S` has no API equivalent). If the test set shows code moving between files, that is the trigger for the clone fallback.

**Order of work inside this plan:**
1. Tools (above) with unit tests: no LLM, $0.
2. Extend `data/ground_truth.yaml` with the introducing commit and PR for the 10 advisories, verified by hand with these tools.
3. OpenRouter client, cost tracking, budget cap, LLM cache.
4. The LangGraph agent using the tools, measured against the ground truth.

## Definition of Done
- [ ] All 8 tools have unit tests (mocked API), including truncation, bad inputs and the "fix only adds lines" case.
- [ ] Running `blame` on the parent of each ground-truth fix commit works for all 10 advisories (no GraphQL errors or timeouts), or the failures are recorded.
- [ ] The ground truth has a hand-verified introducing commit (and PR, or none) for each of the 10 advisories, with links and the reasoning fields filled in.
- [ ] Every introducing commit the agent reports has all reasoning fields, and every `vulnerable_code` quote is found in that commit's diff (checked by code, not by the model).
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
**Status: done, with known gaps** (2026-10-19). Commands: `tracer eval-intro [--ids ...]` → `output/intro_eval_results.yaml`.

**Agent (`agent.py`, LangGraph):** deterministic head start (blamed vulnerable lines and the introduction window) → investigator tool loop (max 12 steps, 20 tool calls) → Opus judge (one structured call) → code checks: the SHA exists, it is an ancestor of a fix commit, the `vulnerable_code` quote is in its added lines, and the PR is looked up via the API.

**Ground truth, 5 of 10 advisories run:**

| Advisory | Introducing commit | PR | Check | Cost |
|---|---|---|---|---|
| requests GHSA-j8r2 | 4d8cb324 ✅ | #1951 ✅ | verified | ~$0.03 |
| langflow GHSA-4f6c | d3d06be8 ✅ | #8271 ✅ | verified | ~$0.03 |
| hydra GHSA-5jjj | 0c2af39b ✅ | #1909 ✅ | verified | $0.031 |
| jinja GHSA-h5c8 | 450756b9 ✅ | none ✅ | verified | $0.066 (V4 Pro) |
| mcp GHSA-84m7 | e4e119b3 ✅ | #641 ✅ | verified | $0.134 (V4 Pro) |

**5/5 commit and PR correct, all passing the code checks; about $0.03–0.13 per advisory.**

**Model decision:** investigator DeepSeek V4.1 Flash got 3/5; on jinja and mcp it gathered too little evidence and the judge correctly answered "not found" rather than guessing. Switching the investigator to `deepseek/deepseek-v4-pro` ($0.43/$0.86) solved both, so it is now the default. Judge: `anthropic/claude-opus-5.5` (~$0.026 per call). Opus 5.5 rejects a forced `tool_choice`, so structured output is requested by instruction and validated.

**Clone fallback:** not needed. All 5 were solved through the GitHub API alone (REST plus GraphQL blame).

**Other findings during the build:**
- Blame often lands on reformat commits ("Style changes", black, pyupgrade); the agent walks past them.
- The affected-range lower bound is a strong free signal (tool 9). Only the lowest bound per package counts, and fork merges are boosted in its ranking.
- Release-branch twins exist (jupyterlab 4.5.x): an introducing commit only has to precede *a* fix commit, not the main-branch one.

**Remaining 5, run later in parallel (`--workers 5`):** jupyterlab ✅ (verified), wger ✅ (plausible: quote not matched), urllib3 ❌ (wrong commit, flagged plausible, not verified), pydantic-ai ❌ and CairoSVG ❌ (not found). **Final: 7/10 commit and PR correct; no wrong answer marked verified.**

**Known gaps:**
- The 3 misses above (renamed or moved code, and bugs dating back to the initial commit).
- **The "rejected and retried" rule is not implemented.** The judge runs once; an answer that fails the code checks is reported with its verdict but not retried with the failure reason.
- Budget-cap stop not tested by a run (the code checks the cap before every call).
- No unit tests yet for `llm.py` and `agent.py`.
