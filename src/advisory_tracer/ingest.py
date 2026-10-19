"""Fetch advisories, keep the ones we can trace (code hosted on GitHub), and save them."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from advisory_tracer.github_client import GitHubClient
from advisory_tracer.models import Advisory

log = logging.getLogger(__name__)


@dataclass
class FetchResult:
    advisories: list[Advisory] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # GHSA IDs with no GitHub repo


def fetch_advisories(
    client: GitHubClient,
    *,
    ecosystem: str | None,
    limit: int,
    ids: list[str] | None = None,
    ttl_seconds: float | None = None,
) -> FetchResult:
    """Fetch specific advisories by ID, or the newest `limit` traceable ones in an ecosystem."""
    result = FetchResult()
    if ids:
        for ghsa_id in ids:
            _add(result, client.get_advisory(ghsa_id, ttl_seconds=ttl_seconds))
        return result

    per_page = min(100, max(limit * 2, 10))  # Over-fetch a little: some get filtered out.
    for raw in client.iter_advisories(
        ecosystem=ecosystem, per_page=per_page, ttl_seconds=ttl_seconds
    ):
        _add(result, raw)
        if len(result.advisories) >= limit:
            break
    return result


def _add(result: FetchResult, raw: dict[str, Any]) -> None:
    if raw.get("withdrawn_at"):
        log.info("skipping %s: withdrawn", raw.get("ghsa_id"))
        result.skipped.append(str(raw.get("ghsa_id")))
        return
    advisory = Advisory.from_api(raw)
    if advisory is None:
        log.info("skipping %s: no GitHub repository found", raw.get("ghsa_id"))
        result.skipped.append(str(raw.get("ghsa_id")))
        return
    result.advisories.append(advisory)


def save_advisories(advisories: list[Advisory], output_dir: Path) -> Path:
    """Write one JSON file per advisory under output_dir/advisories/. Returns that directory."""
    target = output_dir / "advisories"
    target.mkdir(parents=True, exist_ok=True)
    for advisory in advisories:
        path = target / f"{advisory.ghsa_id}.json"
        path.write_text(
            json.dumps(advisory.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8"
        )
    return target
