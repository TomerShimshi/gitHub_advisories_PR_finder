# Plan 1: Foundation and advisory ingestion

**Status:** Not started
**Uses LLM:** No

## Goal
A Dockerized project skeleton that fetches GitHub advisories with a personal access token and stores them locally, ready for the next stages.

## Deliverable
- **Package layout:** `src/` package with separate modules for config, GitHub client, models, CLI.
- **Config:** settings loaded from environment variables (`GITHUB_TOKEN`, `OPENROUTER_API_KEY`, budget cap, cache dir). A committed `.env.example` with placeholder values.
- **Models (Pydantic):** the advisory as we use it (GHSA ID, CVE, summary, severity, CWE, repo, affected and patched version ranges, references), plus a first draft of the YAML output schema (fix commit/PR, introducing commit/PR, each with evidence, confidence, verdict).
- **GitHub client:** `GET /advisories` with filters for ecosystem (`pip`), type (`reviewed`), count, and specific GHSA IDs. Keeps only advisories whose source code is on GitHub. Pagination, retry with backoff, rate-limit awareness, on-disk response cache.
- **CLI:** `fetch` command.
- **Docker:** slim Python image, non-root user, read-only root filesystem. `compose.yml` passes `.env` through `env_file` (never copied into the image) and mounts only `output/` and `cache/`.
- **Tests:** pytest with recorded API responses (no network in unit tests).

## Definition of Done
- [ ] `docker compose run --rm tracer fetch --ecosystem pip --limit 5` writes 5 advisories to `output/` on the host.
- [ ] `docker compose run --rm tracer fetch --ids GHSA-xxxx-xxxx-xxxx` fetches exactly that advisory.
- [ ] Running the same command again makes zero network calls (visible in logs as cache hits).
- [ ] An invalid token produces a single clear error message and a non-zero exit code, not a stack trace.
- [ ] `docker compose run --rm tracer whoami` (or a check in the logs) shows the container runs as a non-root user.
- [ ] No files appear on the host outside `output/` and `cache/`.
- [ ] `docker compose run --rm tests` passes.

## Security notes to leave in the code
- Token handling: read from the environment only, never logged. With more time: secret manager, fine-grained read-only token.

## Risks
- Advisory API rate limits: mitigated by caching.
- Some advisories link a repo only through references, not `source_code_location`: handle both, log the ones we skip.

## Changes from earlier plans
_None (first plan)._

## Results
_Fill in when done: what worked, what did not, numbers, decisions that affect later plans._
