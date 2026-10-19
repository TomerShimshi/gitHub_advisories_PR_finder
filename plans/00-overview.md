# Plans overview

Tool: pulls GitHub security advisories and, for each one, finds the commit and PR that introduced the vulnerability and the commit and PR that fixed it. Built with LangGraph and OpenRouter, output as YAML, checked by an independent verifier.

Scored on: success rate, cost savings (out of a $150 budget), production readiness.

## Order

| # | Plan | Uses LLM | Status |
|---|------|----------|--------|
| 1 | [Foundation and advisory ingestion](01-foundation-and-ingestion.md) | No | Done |
| 2 | [Deterministic fix-side resolver](02-fix-resolver.md) | No | Done |
| 3 | [LLM client, cost tracking, introducing-commit agent](03-introducing-commit-agent.md) | Yes | Not started |
| 4 | [Full pipeline, YAML report, verifier](04-pipeline-and-verifier.md) | Yes | Not started |
| 5 | [Evaluation, cost tuning, production readiness](05-eval-and-hardening.md) | Yes | Not started |
| 6 | [Bonus 1: parallel agents](06-bonus-parallel.md) | Yes | Blocked on 5 |
| 7 | [Bonus 2: Docker Compose generation](07-bonus-docker-generation.md) | Yes | Blocked on 5 |

Plan 5 is the "main objective done" gate. Bonuses start only after it passes.

## Ground rules

- **Everything runs in Docker.** Code is edited on the host but never runs there; the host only needs Docker Desktop.
- **API-only for the main objective.** No cloning. A blobless, no-checkout clone is a fallback only if Plan 3 shows the API is not enough.
- **Deterministic first, LLM second.** Anything an API call or a regex can answer does not go to a model.
- **Honest gaps.** "Not found" with a reason beats a confident wrong answer.
- **Security is simple and commented.** Dangerous areas get a `# SECURITY:` comment saying how they would be hardened with more time.
- **Ecosystem:** start with PyPI; keep the design ecosystem-agnostic.

## Living plans

The project may not be linear. When a plan finishes, fill in its **Results** section, then update the later plans' **Changes from earlier plans** sections and this table.
