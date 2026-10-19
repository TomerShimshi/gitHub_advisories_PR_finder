"""Command-line entry point: `tracer <command> ...`."""

import argparse
import logging
import re
import sys

from advisory_tracer.cache import DiskCache
from advisory_tracer.config import Settings
from advisory_tracer.github_client import GitHubAuthError, GitHubClient, GitHubError
from advisory_tracer.ingest import fetch_advisories, save_advisories

log = logging.getLogger("advisory_tracer")

_GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tracer", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    fetch = sub.add_parser("fetch", help="Fetch GitHub advisories and save them to the output dir.")
    fetch.add_argument("--ecosystem", default="pip", help="Package ecosystem (default: pip).")
    fetch.add_argument("--limit", type=int, default=10, help="How many advisories (default: 10).")
    fetch.add_argument(
        "--ids", nargs="+", metavar="GHSA_ID", help="Fetch these advisories instead of a list."
    )
    fetch.add_argument("--refresh", action="store_true", help="Ignore cached API responses.")
    return parser


def _cmd_fetch(args: argparse.Namespace, settings: Settings) -> int:
    if args.ids:
        bad = [i for i in args.ids if not _GHSA_RE.match(i)]
        if bad:
            log.error("not valid GHSA IDs: %s", ", ".join(bad))
            return EXIT_CONFIG
    if args.limit < 1:
        log.error("--limit must be at least 1")
        return EXIT_CONFIG

    ttl = 0.0 if args.refresh else settings.advisory_cache_ttl_hours * 3600
    token = settings.github_token.get_secret_value() if settings.github_token else None
    with GitHubClient(
        token,
        DiskCache(settings.cache_dir),
        base_url=settings.github_api_url,
        timeout=settings.http_timeout_seconds,
        max_retries=settings.http_max_retries,
    ) as client:
        result = fetch_advisories(
            client, ecosystem=args.ecosystem, limit=args.limit, ids=args.ids, ttl_seconds=ttl
        )
        stats = client.stats

    target = save_advisories(result.advisories, settings.output_dir)
    for advisory in result.advisories:
        log.info("saved %s  %s  %s", advisory.ghsa_id, advisory.repo.full_name, advisory.summary)
    log.info(
        "done: saved=%d skipped=%d network_calls=%d cache_hits=%d dir=%s",
        len(result.advisories),
        len(result.skipped),
        stats.network_calls,
        stats.cache_hits,
        target,
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = Settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if settings.github_token is None:
        log.error("GITHUB_TOKEN is not set. Add it to your .env file (see README).")
        return EXIT_CONFIG

    try:
        if args.command == "fetch":
            return _cmd_fetch(args, settings)
    except GitHubAuthError as exc:
        log.error("%s", exc)
        return EXIT_CONFIG
    except GitHubError as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
