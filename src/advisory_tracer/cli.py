"""Command-line entry point: `tracer <command> ...`."""

import argparse
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from advisory_tracer.agent import IntroducingAgent
from advisory_tracer.cache import DiskCache
from advisory_tracer.config import Settings
from advisory_tracer.evaluate import TruthEntry, format_table, load_ground_truth, score_fix
from advisory_tracer.fix_resolver import FixResolver
from advisory_tracer.github_client import GitHubAuthError, GitHubClient, GitHubError
from advisory_tracer.ingest import FetchResult, fetch_advisories, save_advisories
from advisory_tracer.llm import LLM, BudgetExceeded, CostTracker, load_prices
from advisory_tracer.models import Advisory, AdvisoryReport, CommitFinding, FixFinding
from advisory_tracer.pipeline import Pipeline
from advisory_tracer.report import write_yaml

log = logging.getLogger("advisory_tracer")

_GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2


def _add_selection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ecosystem", default="pip", help="Package ecosystem (default: pip).")
    parser.add_argument("--limit", type=int, default=10, help="How many advisories (default: 10).")
    parser.add_argument(
        "--ids", nargs="+", metavar="GHSA_ID", help="Use these advisories instead of a list."
    )
    parser.add_argument("--refresh", action="store_true", help="Ignore cached API responses.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tracer", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    fetch = sub.add_parser("fetch", help="Fetch advisories and save them to the output dir.")
    _add_selection_args(fetch)

    resolve = sub.add_parser("resolve-fix", help="Find fix commits and PRs (no LLM).")
    _add_selection_args(resolve)

    evaluate = sub.add_parser("eval-fix", help="Run resolve-fix on the ground truth and score it.")
    evaluate.add_argument("--ground-truth", type=Path, default=Path("data/ground_truth.yaml"))
    evaluate.add_argument("--refresh", action="store_true", help="Ignore cached API responses.")

    run = sub.add_parser("run", help="Full pipeline (fix + introducing) -> output/report.yaml.")
    _add_selection_args(run)
    run.add_argument("--workers", type=int, default=4, help="Advisories traced in parallel.")

    intro = sub.add_parser("eval-intro", help="Run the introducing-commit agent and score it.")
    intro.add_argument("--ground-truth", type=Path, default=Path("data/ground_truth.yaml"))
    intro.add_argument("--ids", nargs="+", metavar="GHSA_ID", help="Only these entries.")
    intro.add_argument("--workers", type=int, default=5, help="Advisories traced in parallel.")
    intro.add_argument("--refresh", action="store_true", help="Ignore cached API responses.")
    return parser


def _validate_selection(args: argparse.Namespace) -> bool:
    if args.ids:
        bad = [i for i in args.ids if not _GHSA_RE.match(i)]
        if bad:
            log.error("not valid GHSA IDs: %s", ", ".join(bad))
            return False
    if args.limit < 1:
        log.error("--limit must be at least 1")
        return False
    return True


def _open_client(settings: Settings, refresh: bool) -> GitHubClient:
    token = settings.github_token.get_secret_value() if settings.github_token else None
    return GitHubClient(
        token,
        DiskCache(settings.cache_dir),
        base_url=settings.github_api_url,
        timeout=settings.http_timeout_seconds,
        max_retries=settings.http_max_retries,
        mutable_ttl_seconds=0.0 if refresh else settings.advisory_cache_ttl_hours * 3600,
    )


def _select(client: GitHubClient, args: argparse.Namespace, settings: Settings) -> FetchResult:
    ttl = 0.0 if args.refresh else settings.advisory_cache_ttl_hours * 3600
    return fetch_advisories(
        client, ecosystem=args.ecosystem, limit=args.limit, ids=args.ids, ttl_seconds=ttl
    )


def _log_stats(client: GitHubClient, **extra: object) -> None:
    details = " ".join(f"{k}={v}" for k, v in extra.items())
    log.info(
        "done: %s network_calls=%d cache_hits=%d",
        details,
        client.stats.network_calls,
        client.stats.cache_hits,
    )


def _cmd_fetch(args: argparse.Namespace, settings: Settings) -> int:
    if not _validate_selection(args):
        return EXIT_CONFIG
    with _open_client(settings, args.refresh) as client:
        result = _select(client, args, settings)
        target = save_advisories(result.advisories, settings.output_dir)
        for a in result.advisories:
            log.info("saved %s  %s  %s", a.ghsa_id, a.repo.full_name, a.summary)
        _log_stats(client, saved=len(result.advisories), skipped=len(result.skipped), dir=target)
    return EXIT_OK


def _cmd_resolve_fix(args: argparse.Namespace, settings: Settings) -> int:
    if not _validate_selection(args):
        return EXIT_CONFIG
    with _open_client(settings, args.refresh) as client:
        advisories = _select(client, args, settings).advisories
        resolver = FixResolver(client)
        reports = []
        for advisory in advisories:
            report = AdvisoryReport(
                ghsa_id=advisory.ghsa_id,
                cve_id=advisory.cve_id,
                repo=advisory.repo.full_name,
                summary=advisory.summary,
            )
            try:
                report.fix = resolver.resolve(advisory)
            except GitHubAuthError:
                raise
            except GitHubError as exc:  # One bad advisory must not stop the rest.
                report.error = str(exc)
                log.warning("%s failed: %s", advisory.ghsa_id, exc)
            reports.append(report)
            primary = report.fix.primary
            log.info(
                "%s  fix=%s  pr=%s  confidence=%s  commits=%d  candidates=%d",
                advisory.ghsa_id,
                primary.sha[:12] if primary.sha else "not_found",
                f"#{primary.pr_number}" if primary.pr_number else "-",
                primary.confidence.value,
                len(report.fix.commits),
                len(report.fix.candidates),
            )
        path = write_yaml(reports, settings.output_dir / "fix_results.yaml")
        _log_stats(client, advisories=len(reports), file=path)
    return EXIT_OK


def _cmd_eval_fix(args: argparse.Namespace, settings: Settings) -> int:
    if not args.ground_truth.exists():
        log.error("ground truth file not found: %s", args.ground_truth)
        return EXIT_CONFIG
    truth = load_ground_truth(args.ground_truth)
    resolve_args = argparse.Namespace(
        ids=[t.ghsa_id for t in truth], ecosystem=None, limit=len(truth), refresh=args.refresh
    )
    with _open_client(settings, args.refresh) as client:
        advisories = {a.ghsa_id: a for a in _select(client, resolve_args, settings).advisories}
        resolver = FixResolver(client)
        scores = []
        reports = []
        for entry in truth:
            finding = resolver.resolve(advisories[entry.ghsa_id])
            scores.append(score_fix(entry, finding))
            reports.append(AdvisoryReport(ghsa_id=entry.ghsa_id, repo=entry.repo, fix=finding))
        write_yaml(reports, settings.output_dir / "fix_eval_results.yaml")
        print(format_table(scores))
        _log_stats(client, advisories=len(truth))
    return EXIT_OK


def _cmd_eval_intro(args: argparse.Namespace, settings: Settings) -> int:
    """Run the introducing-commit agent on the ground truth and score it."""
    if settings.openrouter_api_key is None:
        log.error("OPENROUTER_API_KEY is not set")
        return EXIT_CONFIG
    truth = [
        t for t in load_ground_truth(args.ground_truth) if not args.ids or t.ghsa_id in args.ids
    ]
    key = settings.openrouter_api_key.get_secret_value()
    cache = DiskCache(settings.cache_dir)
    tracker = CostTracker(settings.budget_usd, settings.advisory_budget_usd)
    tracker.prices = load_prices(cache, key, settings.openrouter_base_url)

    def make(model: str, max_tokens: int) -> LLM:
        return LLM(model, api_key=key, base_url=settings.openrouter_base_url, tracker=tracker,
                   cache=cache, max_tokens=max_tokens)

    rows = []
    with _open_client(settings, args.refresh) as client:
        agent = IntroducingAgent(
            client, make(settings.investigator_model, 4096), make(settings.judge_model, 2048),
            settings.tool_call_budget,
        )
        resolver = FixResolver(client)
        reports = []

        def trace(entry: TruthEntry) -> tuple[FixFinding, CommitFinding] | None:
            advisory = Advisory.from_api(client.get_advisory(entry.ghsa_id))
            assert advisory is not None
            fix = resolver.resolve(advisory)
            try:
                return fix, agent.run(advisory, fix)
            except BudgetExceeded as exc:
                log.error("%s skipped: %s", entry.ghsa_id, exc)
                return None

        # Advisories are independent: run them in parallel (cost tracker and caches are
        # thread-safe). Results keep ground-truth order.
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            results = list(pool.map(trace, truth))
        for entry, result in zip(truth, results, strict=True):
            if result is None:
                continue
            fix, found = result
            accepted = {c.sha: c.pr for c in entry.introduced.commits} if entry.introduced else {}
            ok = found.sha is not None and found.sha in accepted
            pr_ok = found.sha is not None and ok and found.pr_number == accepted.get(found.sha)
            rows.append((entry.ghsa_id, (found.sha or "not_found")[:12], ok, pr_ok,
                         found.verdict.value, tracker.spent_on(entry.ghsa_id)))
            reports.append(AdvisoryReport(ghsa_id=entry.ghsa_id, repo=entry.repo, fix=fix,
                                          introduced=found,
                                          cost_usd=tracker.spent_on(entry.ghsa_id)))
            write_yaml(reports, settings.output_dir / "intro_eval_results.yaml")
    print(f"{'advisory':<22}{'answer':<14}{'commit':<8}{'pr':<6}{'check':<11}{'cost':>9}")
    for gid, sha, ok, pr_ok, verdict, cost in rows:
        print(f"{gid:<22}{sha:<14}{'yes' if ok else 'NO':<8}{'yes' if pr_ok else 'NO':<6}"
              f"{verdict:<11}${cost:>8.4f}")
    print(f"introducing commit ok: {sum(r[2] for r in rows)}/{len(rows)}   "
          f"PR ok: {sum(r[3] for r in rows)}/{len(rows)}   total cost: ${tracker.spent_usd:.4f}")
    return EXIT_OK


def _cmd_run(args: argparse.Namespace, settings: Settings) -> int:
    """The full pipeline: fix and introducing commits/PRs, verified -> output/report.yaml."""
    if not _validate_selection(args):
        return EXIT_CONFIG
    if settings.openrouter_api_key is None:
        log.error("OPENROUTER_API_KEY is not set")
        return EXIT_CONFIG
    with _open_client(settings, args.refresh) as client:
        pipeline = Pipeline(client, settings)
        reports: list[AdvisoryReport] = []
        stopped = None
        path = settings.output_dir / "report.yaml"
        advisories = _select(client, args, settings).advisories

        def trace(advisory: Advisory) -> AdvisoryReport | None:
            nonlocal stopped
            try:
                return pipeline.trace(advisory)
            except BudgetExceeded as exc:
                stopped = str(exc)
                log.error("%s skipped: %s", advisory.ghsa_id, exc)
                return None

        # Advisories are independent: trace them in parallel (bounded to respect rate limits).
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for report in pool.map(trace, advisories):
                if report is None:
                    continue
                reports.append(report)
                pipeline.write(reports, path, stopped)  # Partial results survive a crash.
                log.info(
                    "%s  fix=%s pr=%s  introduced=%s pr=%s (%s)  $%.4f",
                    report.ghsa_id,
                    (report.fix.primary.sha or "not_found")[:12],
                    report.fix.primary.pr_number,
                    (report.introduced.sha or "not_found")[:12],
                    report.introduced.pr_number,
                    report.introduced.verdict.value,
                    report.cost_usd,
                )
        pipeline.write(reports, path, stopped)
        log.info("report: %s  total cost $%.4f", path, pipeline.tracker.spent_usd)
    return EXIT_OK


_COMMANDS = {
    "fetch": _cmd_fetch,
    "resolve-fix": _cmd_resolve_fix,
    "eval-fix": _cmd_eval_fix,
    "eval-intro": _cmd_eval_intro,
    "run": _cmd_run,
}


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = Settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # httpx logs every request at INFO; keep it for debugging only.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if settings.github_token is None:
        log.error("GITHUB_TOKEN is not set. Add it to your .env file (see README).")
        return EXIT_CONFIG

    try:
        return _COMMANDS[args.command](args, settings)
    except GitHubAuthError as exc:
        log.error("%s", exc)
        return EXIT_CONFIG
    except GitHubError as exc:
        log.error("%s", exc)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
