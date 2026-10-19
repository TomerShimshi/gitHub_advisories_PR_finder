"""GitHub REST client: auth, retries, rate limits, pagination, and an on-disk response cache."""

import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx

from advisory_tracer.cache import DiskCache

log = logging.getLogger(__name__)

_CACHE_NAMESPACE = "github"
# Wait for a rate-limit reset only if it is this close; otherwise fail fast with a clear message.
_MAX_RATE_LIMIT_WAIT_SECONDS = 90
_RETRYABLE_STATUS = {500, 502, 503, 504}


class GitHubError(Exception):
    """Base class for GitHub API failures."""


class GitHubAuthError(GitHubError):
    """The token is missing, invalid, or lacks access."""


class GitHubNotFoundError(GitHubError):
    """The requested resource does not exist."""


class GitHubRateLimitError(GitHubError):
    """The rate limit is exhausted and resets too far in the future to wait."""


@dataclass
class CallStats:
    network_calls: int = 0
    cache_hits: int = 0


class GitHubClient:
    def __init__(
        self,
        token: str | None,
        cache: DiskCache | None,
        *,
        base_url: str = "https://api.github.com",
        timeout: float = 30.0,
        max_retries: int = 3,
        transport: httpx.BaseTransport | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "advisory-tracer",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(
            base_url=base_url, headers=headers, timeout=timeout, transport=transport
        )
        self._cache = cache
        self._max_retries = max_retries
        self._sleep = sleep
        self.stats = CallStats()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- Public API ----------------------------------------------------------------------------

    def get_advisory(self, ghsa_id: str, *, ttl_seconds: float | None = None) -> dict[str, Any]:
        data, _ = self._get(f"/advisories/{ghsa_id}", None, ttl_seconds)
        return dict(data)

    def iter_advisories(
        self,
        *,
        ecosystem: str | None = None,
        advisory_type: str = "reviewed",
        per_page: int = 100,
        ttl_seconds: float | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield global advisories page by page, newest first."""
        first_params: dict[str, Any] = {"type": advisory_type, "per_page": per_page}
        if ecosystem:
            first_params["ecosystem"] = ecosystem
        params: dict[str, Any] | None = first_params
        url: str | None = "/advisories"
        while url:
            page, url = self._get(url, params, ttl_seconds)
            params = None  # The "next" link already carries the query string.
            yield from page

    # --- Internals -----------------------------------------------------------------------------

    def _get(
        self, url: str, params: dict[str, Any] | None, ttl_seconds: float | None
    ) -> tuple[Any, str | None]:
        """GET with caching. Returns (json body, next page URL or None)."""
        key = str(self._http.build_request("GET", url, params=params).url)
        if self._cache is not None:
            cached = self._cache.get(_CACHE_NAMESPACE, key, ttl_seconds)
            if cached is not None:
                self.stats.cache_hits += 1
                log.debug("cache hit %s", key)
                return cached["body"], cached["next"]

        response = self._request_with_retries(url, params)
        body = response.json()
        next_url = response.links.get("next", {}).get("url")
        if self._cache is not None:
            self._cache.set(_CACHE_NAMESPACE, key, {"body": body, "next": next_url})
        return body, next_url

    def _request_with_retries(self, url: str, params: dict[str, Any] | None) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            last_attempt = attempt == self._max_retries
            try:
                self.stats.network_calls += 1
                response = self._http.get(url, params=params)
            except httpx.TransportError as exc:
                if last_attempt:
                    raise GitHubError(f"network error calling GitHub: {exc}") from exc
                self._backoff(attempt, f"network error: {exc}")
                continue

            if response.status_code == 401:
                raise GitHubAuthError(
                    "GitHub rejected the token (401). Check GITHUB_TOKEN in your .env file."
                )
            if response.status_code in (403, 429) and self._is_rate_limited(response):
                wait = self._rate_limit_wait(response)
                if wait is None or wait > _MAX_RATE_LIMIT_WAIT_SECONDS or last_attempt:
                    raise GitHubRateLimitError(
                        f"GitHub rate limit hit; resets in {wait or 'unknown'}s. "
                        "Rerun later (cached results are kept)."
                    )
                log.warning("rate limited, waiting %.0fs", wait)
                self._sleep(wait)
                continue
            if response.status_code == 403:
                raise GitHubAuthError(
                    f"GitHub denied access (403) to {url}: {_message(response)}"
                )
            if response.status_code == 404:
                raise GitHubNotFoundError(f"not found: {url}")
            if response.status_code in _RETRYABLE_STATUS and not last_attempt:
                self._backoff(attempt, f"HTTP {response.status_code}")
                continue
            if response.is_error:
                raise GitHubError(
                    f"GitHub returned HTTP {response.status_code} for {url}: {_message(response)}"
                )
            return response
        raise AssertionError("unreachable")

    def _backoff(self, attempt: int, reason: str) -> None:
        delay = 2**attempt
        log.warning("retrying in %ss after %s", delay, reason)
        self._sleep(delay)

    @staticmethod
    def _is_rate_limited(response: httpx.Response) -> bool:
        return (
            response.headers.get("x-ratelimit-remaining") == "0"
            or "retry-after" in response.headers
            or "rate limit" in _message(response).lower()
        )

    @staticmethod
    def _rate_limit_wait(response: httpx.Response) -> float | None:
        if "retry-after" in response.headers:
            return float(response.headers["retry-after"])
        reset = response.headers.get("x-ratelimit-reset")
        if reset is not None:
            return max(0.0, float(reset) - time.time()) + 1
        return None


def _message(response: httpx.Response) -> str:
    try:
        return str(response.json().get("message", ""))
    except ValueError:
        return response.text[:200]
