# gitHub_advisories_PR_finder

Pulls GitHub security advisories with a personal GitHub token and, for each one, finds the commit and pull request that **introduced** the vulnerability and the commit and pull request that **fixed** it. Output is YAML. Everything runs inside Docker; the host only needs Docker.

## How it works

```
fetch advisories (GitHub REST, PyPI by default)
  -> fix resolver (deterministic, no LLM)
       1. commits / PRs / compare URLs linked in the advisory
       2. GitHub search for the GHSA / CVE ID
       3. release range (last vulnerable tag ... patched tag) as ranked candidates, never a guess
  -> introducing-commit agent (LangGraph)
       investigator: DeepSeek V4 Pro, calls read-only GitHub tools (blame, diffs, file history, ...)
       judge: Claude Opus 5.5, called once per advisory on a compact evidence report (no raw diffs)
  -> deterministic checks (code, not the model)
       introducing commit must exist and be an ancestor of a fix commit
       the quoted vulnerable code must appear in that commit's added lines
       PR looked up through the API (commits/{sha}/pulls)
  -> YAML
```

Each answer carries a verdict: `verified` (precedes the fix and the quote is found), `plausible` (precedes the fix, quote not found) or `rejected`. "Not found" with a reason is preferred over a confident wrong answer.

## Setup

Requirements: Docker Desktop (or Docker Engine with Compose v2), a GitHub token, an OpenRouter API key.

1. Copy `.env.example` to `.env` and fill in `GITHUB_TOKEN` and `OPENROUTER_API_KEY`. `.env` is git-ignored and never copied into the image.
2. Build: `docker compose build`

### Creating the GitHub token

1. GitHub -> **Settings** -> **Developer settings** -> **Personal access tokens** -> **Fine-grained tokens** -> **Generate new token** (direct link: https://github.com/settings/personal-access-tokens/new).
2. **Token name:** e.g. `advisory-tracer`. **Expiration:** 30 days is plenty.
3. **Repository access:** choose **Public repositories (read-only)**.
4. **Permissions:** leave everything as is. Public advisories, commits and pull requests are readable without extra permissions.
5. Click **Generate token**, copy it (it starts with `github_pat_` and is shown only once) and put it in `.env`: `GITHUB_TOKEN=github_pat_...`

A token raises the API limit from 60 to 5,000 requests per hour.

Optional settings (env vars, see `src/advisory_tracer/config.py`): `BUDGET_USD` (default 5.0), `ADVISORY_BUDGET_USD` (0.50), `TOOL_CALL_BUDGET` (20), `INVESTIGATOR_MODEL`, `JUDGE_MODEL`, `ADVISORY_CACHE_TTL_HOURS` (24), `LOG_LEVEL`.

## Usage

```sh
# Full pipeline: fix + introducing commits and PRs, verified -> output/report.yaml
docker compose run --rm tracer run --ids GHSA-j8r2-6x86-q33q
docker compose run --rm tracer run --ecosystem pip --limit 5 --workers 4   # parallel advisories

# Fetch advisories -> output/advisories/<GHSA_ID>.json
docker compose run --rm tracer fetch --ecosystem pip --limit 5
docker compose run --rm tracer fetch --ids GHSA-xxxx-xxxx-xxxx GHSA-yyyy-yyyy-yyyy

# Fix commit(s) and PR(s), no LLM -> output/fix_results.yaml
docker compose run --rm tracer resolve-fix --limit 20
docker compose run --rm tracer resolve-fix --ids GHSA-j8r2-6x86-q33q

# Score the fix resolver against data/ground_truth.yaml -> output/fix_eval_results.yaml
docker compose run --rm tracer eval-fix

# Run the introducing-commit agent on the ground truth and score it -> output/intro_eval_results.yaml
docker compose run --rm tracer eval-intro
docker compose run --rm tracer eval-intro --ids GHSA-j8r2-6x86-q33q
```

`--refresh` ignores cached API responses. GitHub and LLM responses are cached in `cache/`, so reruns make no network calls and cost nothing. `eval-intro` writes its YAML after every advisory, so a run stopped by the budget keeps its partial results.

## Cost controls

- **Deterministic first.** Anything an API call or a regex can answer does not go to a model. The fix side costs $0.
- **Cheap model for the loop, expensive model once.** The tool-calling loop (many calls, large inputs) runs on DeepSeek V4 Pro ($0.43 / $0.86 per 1M tokens in/out; V4.1 Flash at $0.033 / $0.08 is a one-variable switch, `INVESTIGATOR_MODEL`). Claude Opus 5.5 ($4 / $20) is called once per advisory on a compact dossier.
- **Deterministic head start.** The agent starts with the fix's vulnerable lines already blamed and the introduction window (commits between the last unaffected and first affected release), which saves paid round-trips.
- **Trimmed diffs.** Tools send only relevant hunks with size caps; tests, docs, lockfiles and changelogs are listed but not sent.
- **On-disk caches** for GitHub responses (immutable commit data never expires) and LLM responses (identical requests are never paid twice).
- **Hard caps.** `BUDGET_USD` per run and `ADVISORY_BUDGET_USD` per advisory stop cleanly; `TOOL_CALL_BUDGET` limits tool calls per advisory, and the investigator has a step limit.
- **Live prices.** Cost is computed from OpenRouter's model list (cached 24 h), with pinned fallback prices.
- **Compare API trick.** GitHub's compare endpoint always returns the full diff (2.6 to 3.7 MB per call). Ancestry is checked as `branch...commit`, whose diff is empty when the answer is yes, and responses are trimmed before caching. The cache went from 65 MB to 4 MB.

## Results

### Fix commit and PR (deterministic, $0)

Ground truth (10 advisories, `eval-fix`):

| Metric | Result |
|---|---|
| Fix commit correct (or correctly deferred) | 10/10 |
| Primary commit exactly as hand-picked | 9/10 (the 10th is wger, deferred to the agent) |
| Fix PR correct | 10/10 |
| All fix commits found (backports, multi-part) | 20/20 for the 9 linked advisories |
| Extra commits that aren't fixes | 0 |
| API calls, cold cache | 96 (cached rerun: 0) |
| LLM cost | $0 |

100 newest PyPI advisories (`resolve-fix --limit 100`): 78 fix commits found (77 high confidence, 1 from GHSA search), 15 deferred with candidates, 7 with no candidates, 0 errors. 441 API calls. For wger (fix not linked) the real fix ranks 1st of 371 candidates.

Findings: private security fork merges ("Merge pull request from GHSA-...") have no public PR, and the tool says so instead of inventing one. Fixes can land on non-default branches (langflow), and the tool reports that.

### Introducing-commit results

Ground truth, all 10 advisories (`eval-intro --workers 5`, advisories traced in parallel threads):

| Advisory | Introducing commit | PR | Check | Cost |
|---|---|---|---|---|
| requests GHSA-j8r2-6x86-q33q | 4d8cb324 ✅ | #1951 ✅ | verified | ~$0.03 |
| langflow GHSA-4f6c-2vvp-gw82 | d3d06be8 ✅ | #8271 ✅ | verified | ~$0.03 |
| hydra GHSA-5jjj-9xc3-rm56 | 0c2af39b ✅ | #1909 ✅ | verified | $0.031 |
| jinja GHSA-h5c8-rqwp-cp95 | 450756b9 ✅ | none ✅ | verified | $0.066 |
| mcp GHSA-84m7-p3x7-pcfv | e4e119b3 ✅ | #641 ✅ | verified | $0.134 |
| jupyterlab GHSA-jwrc-gm9j-263p | c5f522db ✅ | none ✅ | verified | $0.070 |
| wger GHSA-c72h-82w6-rqfp | f26a6be4 ✅ | #85 ✅ | plausible (quote not matched) | $0.059 |
| urllib3 GHSA-v845-jxx5-vc9f | 62136b32 ❌ | ❌ | plausible (not verified) | cached |
| pydantic-ai GHSA-4x9p-g9wm-8q7f | not found ❌ | ❌ | — | $0.029 |
| CairoSVG GHSA-c3jg-qh8m-j3h2 | not found ❌ | ❌ | — | $0.141 |

**7/10 introducing commit and PR correct. No wrong answer was marked `verified`:** the one wrong answer (urllib3) failed the quote check and is flagged `plausible`, and the two misses say "not found" instead of guessing. About $0.03–0.14 per advisory, ~$0.60 for all 10; total LLM spend for the whole project is well under $1 of the $150 budget.

The misses are the hardest cases: urllib3's flaw is a missing list entry whose origin passes through several renames, pydantic-ai's vulnerable code was moved by a refactor (only the affected-range lower bound points to the origin), and CairoSVG has two independent bugs dating back to the initial commit. With the cheaper DeepSeek V4.1 Flash investigator jinja and mcp were also missed; V4 Pro solved both, so it is the default.

## Ground truth

`data/ground_truth.yaml` holds 10 hand-checked PyPI advisories. Each entry links the advisory, every fix commit and every PR, and has a `how_verified` note so it can be re-checked by hand. It records:

- **fix**: the primary commit, `also_primary` for fixes in several equal parts, every accepted commit (backports included) with its public PR (`null` when none exists), and `linked: false` when the advisory does not link the fix.
- **introduced**: the introducing commit(s) and PR, plus the same reasoning fields the agent must produce (`vulnerable_code`, `why_vulnerable`, `why_this_commit`, `fix_link`, `confidence`). Each `vulnerable_code` quote was checked by script against the introducing commit's own diff.

"Introducing" follows the usual SZZ definition: the earliest commit that wrote the code the fix changes or guards, skipping commits that only reformat, rename or move it. When the flaw is a missing check, it is the commit that added the unguarded code (or the incomplete check). Each answer was cross-checked against the lower bound of the affected-version range.

## Security

In place:

- Container runs as a non-root user with a read-only filesystem, `cap_drop: ALL`, `no-new-privileges`, and access only to `output/`, `cache/` and `data/` (read-only). The test container has no network.
- Secrets come only from environment variables, are wrapped in `SecretStr` and never logged; `.env` is never copied into the image.
- Advisory references are untrusted: only hex SHAs and numeric PR IDs are extracted, so they are safe in API paths.
- Tool inputs chosen by the model are validated: SHAs must be hex, paths cannot be absolute or contain `..`, and every call is pinned to the advisory's own repo. The model cannot reach other repos or inject URLs. All tools are read-only.
- Repo content (diffs, commit messages, advisory text) is treated as data. Every model answer is checked by code before it is reported.

With more time (from the `# SECURITY:` comments in the code):

- seccomp/AppArmor profiles, an egress allowlist (api.github.com, openrouter.ai only), CPU/memory limits.
- Load tokens from a secret manager and enforce a fine-grained, read-only GitHub token.
- Re-validate owner, repo, SHAs and refs inside the GitHub client too, not only at the callers.
- Allowlist tool paths to files from the fix diff; per-tool rate limits.
- Strip or fence instructions found in repo content before it reaches a prompt.

## Known limitations

- **API only, no git clone.** There is no pickaxe (`git log -S`) search, so code that moved across files is hard to trace.
- **Monorepo sub-packages without version tags** (e.g. `praisonaiagents` in PraisonAI) get no release-range candidates; neither do advisories with no patched version.
- **Missing release tags** (langflow-style) weaken the release-range and introduction-window steps.
- **Unlinked fixes** rely on candidate ranking by word overlap with the advisory text.
- The agent runs today through `eval-intro` on the ground-truth set; `resolve-fix` covers the fix side for any advisory list.
- **The retry only re-asks the judge.** When the verifier marks an answer `plausible` or `rejected`, the graph loops back to the Opus judge once with the failure reason and the claimed commit's real diff, and keeps the best-verified answer. Tested on urllib3: the retry ran ($0.053) but the judge kept the same commit, because the investigator's report never contained the right one. A stronger retry would re-run the investigator with the feedback (~$0.10–0.15 more).
- **No second-opinion LLM verifier.** Plan 4 called for an LLM judge from a third model family (neither DeepSeek nor Claude) to review what the code checks can't settle; only the deterministic checks exist.
- **Agent misses on the ground truth (3/10):** urllib3 (wrong commit, flagged `plausible`), pydantic-ai and CairoSVG (not found): renamed or moved code, and bugs dating back to the initial commit.
- **Tests:** no unit tests yet for `llm.py`, `agent.py` or `pipeline.py`, none that feed the verifier deliberately corrupted answers, and the budget-cap stop has not been triggered in a test (the cap is checked before every call).
- The script that checked the ground truth's quotes, ancestry and links was run during development but is not in the repo.
- Bonus 1 (parallel agents) is partly done: `run` and `eval-intro` trace advisories in a thread pool (`--workers`), sharing the thread-safe cost tracker and caches; there is no shared GitHub rate limiter across threads yet. Bonus 2 (Docker environment generation for web apps) is not implemented.

## Tests

```sh
docker compose run --rm tests    # ruff, mypy (strict), pytest; no network access
```

Unit tests use small mocked API responses. `eval-fix` and `eval-intro` are the real-data regression checks.

## Project layout

```
src/advisory_tracer/
  cli.py            commands: fetch, resolve-fix, eval-fix, eval-intro
  config.py         settings from environment variables
  github_client.py  GitHub REST/GraphQL client: auth, retries, rate limits, pagination, cache
  cache.py          on-disk JSON cache
  ingest.py         fetch advisories, keep ones whose code is on GitHub
  references.py     classify advisory reference URLs (commits, PRs, tags)
  fix_resolver.py   deterministic fix commit / PR resolver
  diffs.py          parse patches: hunks, touched lines, quote checks
  agent_tools.py    read-only tools for the agent (blame, diffs, history, PRs, ancestry, ...)
  llm.py            OpenRouter client: cost tracking, budget caps, response cache
  agent.py          LangGraph introducing-commit agent and deterministic checks
  evaluate.py       score results against data/ground_truth.yaml
  models.py         data models and YAML report schema
  report.py         YAML output
```
