# Plan 4: Full pipeline, YAML report, verifier

**Status:** Not started
**Uses LLM:** Yes

## Goal
One command that goes from advisory IDs to a verified YAML report, where every claim says how it was checked.

## Deliverable
- **LangGraph pipeline:** fetch → resolve fix (Plan 2) → find introducing commit (Plan 3) → verify → write. One failing advisory is recorded as failed and does not stop the others.
- **YAML report:** one entry per advisory with fix commit, fix PR, introducing commit, introducing PR. Each with evidence, confidence, and verifier verdict. Plus per-advisory and total cost, and run metadata (models, timestamps).
- **Verifier, deterministic checks first:**
  - every SHA exists in the repo
  - the introducing commit is an ancestor of the fix commit
  - the fix diff touches the code the introducing commit added
  - each PR actually contains its commit
- **Verifier, LLM judge second:** only for what the checks cannot settle (did this commit really create the flaw, or just touch nearby lines?). Uses a different model family from the one that produced the answer, so they don't share the same blind spots.
- **Verdicts:** `verified`, `plausible`, `rejected`, each with a reason. A rejected claim is downgraded in the report, never silently removed.

## Definition of Done
- [ ] `docker compose run --rm tracer run --ids <IDs>` writes `output/report.yaml`.
- [ ] The report validates against the Pydantic schema.
- [ ] Every claim has evidence, confidence, and a verdict; the report shows the total cost.
- [ ] Tests with deliberately corrupted results are caught by the verifier: a non-existent SHA, swapped introducing and fix commits, a PR that does not contain the commit, an introducing commit unrelated to the fixed code.
- [ ] An advisory that raises an error appears in the report as failed with the error, and the rest of the run completes.

## Security notes to leave in the code
- The YAML writer uses safe dumping; values from repos and advisories are never treated as code.

## Risks
- The LLM judge adds cost: run it only on claims the deterministic checks leave open.

## Changes from earlier plans
_Update after Plan 3._

## Results
_Fill in when done._
