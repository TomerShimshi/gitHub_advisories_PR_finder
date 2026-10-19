"""End-to-end pipeline: advisory -> fix commit/PR (deterministic) -> introducing commit/PR
(agent) -> verified report. One failing advisory is recorded and the run continues."""

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from advisory_tracer.agent import IntroducingAgent
from advisory_tracer.cache import DiskCache
from advisory_tracer.config import Settings
from advisory_tracer.fix_resolver import FixResolver
from advisory_tracer.github_client import GitHubAuthError, GitHubClient, GitHubError
from advisory_tracer.llm import LLM, BudgetExceeded, CostTracker, load_prices
from advisory_tracer.models import Advisory, AdvisoryReport

log = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, client: GitHubClient, settings: Settings) -> None:
        if settings.openrouter_api_key is None:
            raise ValueError("OPENROUTER_API_KEY is not set")
        key = settings.openrouter_api_key.get_secret_value()
        cache = DiskCache(settings.cache_dir)
        self.settings = settings
        self.tracker = CostTracker(settings.budget_usd, settings.advisory_budget_usd)
        self.tracker.prices = load_prices(cache, key, settings.openrouter_base_url)

        def make(model: str, max_tokens: int) -> LLM:
            return LLM(
                model,
                api_key=key,
                base_url=settings.openrouter_base_url,
                tracker=self.tracker,
                cache=cache,
                max_tokens=max_tokens,
            )

        self.resolver = FixResolver(client)
        self.agent = IntroducingAgent(
            client,
            make(settings.investigator_model, 4096),
            make(settings.judge_model, 2048),
            settings.tool_call_budget,
        )

    def trace(self, advisory: Advisory) -> AdvisoryReport:
        """Fix and introducing commits for one advisory. Raises BudgetExceeded (to stop the
        run) and GitHubAuthError; any other failure is recorded in the report."""
        report = AdvisoryReport(
            ghsa_id=advisory.ghsa_id,
            cve_id=advisory.cve_id,
            repo=advisory.repo.full_name,
            summary=advisory.summary,
        )
        try:
            report.fix = self.resolver.resolve(advisory)
            report.introduced = self.agent.run(advisory, report.fix)
        except (BudgetExceeded, GitHubAuthError):
            raise
        except (GitHubError, ValueError) as exc:  # One bad advisory must not stop the run.
            report.error = f"{type(exc).__name__}: {exc}"
            log.warning("%s failed: %s", advisory.ghsa_id, report.error)
        report.cost_usd = round(self.tracker.spent_on(advisory.ghsa_id), 6)
        return report

    def write(self, reports: list[AdvisoryReport], path: Path, stopped: str | None) -> Path:
        """report.yaml: run metadata, cost summary and one entry per advisory."""
        data: dict[str, Any] = {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "models": {
                "investigator": self.settings.investigator_model,
                "judge": self.settings.judge_model,
            },
            "cost": self.tracker.summary(),
            "stopped_early": stopped,
            "advisories": [r.model_dump(mode="json") for r in reports],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=100)
        return path
