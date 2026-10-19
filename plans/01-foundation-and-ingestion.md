# Plan 1: Foundation and advisory ingestion

**Status:** Done (2026-10-19)
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
- [x] `docker compose run --rm tracer fetch --ecosystem pip --limit 5` writes 5 advisories to `output/` on the host.
- [x] `docker compose run --rm tracer fetch --ids GHSA-xxxx-xxxx-xxxx` fetches exactly that advisory.
- [x] Running the same command again makes zero network calls (visible in logs as cache hits).
- [x] An invalid token produces a single clear error message and a non-zero exit code, not a stack trace.
- [x] `docker compose run --rm --entrypoint id tracer` shows the container runs as a non-root user.
- [x] No files appear on the host outside `output/` and `cache/`.
- [x] `docker compose run --rm tests` passes.

## Security notes to leave in the code
- Token handling: read from the environment only, never logged. With more time: secret manager, fine-grained read-only token.

## Risks
- Advisory API rate limits: mitigated by caching.
- Some advisories link a repo only through references, not `source_code_location`: handle both, log the ones we skip.

## Changes from earlier plans
_None (first plan)._

## Results
- Done and verified (2026-10-19): `docker compose run --rm tests` passes ruff, strict mypy and 35 unit tests, with no network access. The container runs as uid 1000 (`app`), the root filesystem is read-only, only `output/` is writable on the host. A missing token gives a clear error and exit code 2.
- Live runs against the real API (2026-10-19):
  - `fetch --limit 5`: 5 advisories saved, 1 network call; the second run had 0 network calls and 1 cache hit.
  - `fetch --ids GHSA-jwrc-gm9j-263p`: 1 advisory saved.
  - A bad token gave `GitHub rejected the token (401)` and exit code 2.
  - The token is not written to the cache (searched `cache/` for it).
- Observed in real data (affects Plan 2):
  - GHSA-jwrc-gm9j-263p (jupyterlab) links **3 fix commits**, one per release branch (4.6.4, 4.5.11, ...). The fix side must be a list, or a primary commit plus backports.
  - The `pip` ecosystem does not mean Python code: that jupyterlab fix is TypeScript. Nothing should assume the language from the ecosystem.
  - References often include the repository's own advisory (`/security/advisories/GHSA-...`) and release tags, which are useful extra signals.
- Decisions for later plans:
  - The HTTP client is synchronous (httpx). Plan 6 can run it in threads, or switch to `httpx.AsyncClient` if needed.
  - `DiskCache` is generic (namespace + key + optional TTL), so Plan 3 reuses it for LLM responses.
  - The report schema draft (`CommitFinding`, `AdvisoryReport`) is in `models.py`. Plan 2 may need a list of fix commits, because one fix can span several commits.
  - Advisories without a GitHub repo, or withdrawn ones, are skipped and logged, not errors.
  - The unit test fixture is a hand-written advisory shaped like the API payload. Plan 2 should add recorded real responses for its ground-truth set.
