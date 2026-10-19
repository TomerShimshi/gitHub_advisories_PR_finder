# Plan 5: Evaluation, cost tuning, production readiness

**Status:** Not started
**Uses LLM:** Yes
**Gate:** the main objective is done when this plan's DoD passes. Bonuses start only after that.

## Goal
Measure how well the tool works and what it costs, cut the cost, and make the code ready for review.

## Deliverable
- **Eval script:** scores `report.yaml` against the ground-truth set: correct, wrong, and not-found counts for each of the four targets, plus cost.
- **Larger ground truth:** grow the set (target 20 to 30 advisories) if Plan 3 results allow it within budget.
- **Cost pass:** route each step to the cheapest model that keeps accuracy; trim prompts and diff snippets; confirm caching; record before and after numbers.
- **Code quality:** linter (ruff), type checker (mypy), tests for the deterministic parts, clear module boundaries, structured logs.
- **README:** what the tool does, how to set up `.env`, how to run it in Docker, sample output, results table, known limitations, total spend.
- **Security comments:** `# SECURITY:` at each dangerous area: token handling, untrusted advisory and repo content (prompt injection), clone fallback (if it exists), running generated Docker files (Plan 7).

## Definition of Done
- [ ] The eval prints a table: accuracy per target, not-found rate, cost per advisory, and total cost.
- [ ] Cost per advisory is lower than at the end of Plan 4, with no drop in accuracy (or the trade-off is documented).
- [ ] Following the README from a fresh clone, `docker compose run --rm tracer run ...` works.
- [ ] `pytest`, `ruff`, and `mypy` all pass inside Docker.
- [ ] Total project spend so far is recorded.

## Changes from earlier plans
_Update after Plan 4._

## Results
_Fill in when done: final numbers for the README._
