"""LLM access through OpenRouter: cost accounting, budget caps and an on-disk response cache.

Every call goes through `LLM.invoke`, which:
  1. refuses to start if the run or advisory budget is already used up,
  2. returns a cached response (cost $0) for an identical earlier request,
  3. otherwise calls the model and records the dollars spent.
"""

import hashlib
import json
import logging
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
from langchain_core.messages import AIMessage, BaseMessage, message_to_dict, messages_from_dict
from langchain_core.utils.function_calling import convert_to_openai_tool
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, SecretStr

from advisory_tracer.cache import DiskCache

log = logging.getLogger(__name__)

_CACHE_NAMESPACE = "llm"
_PRICE_CACHE_KEY = "openrouter-model-prices"
_PRICE_TTL_SECONDS = 24 * 3600

# Fallback prices in USD per million tokens (input, output), checked 2026-10-19. Live prices
# from OpenRouter's model list take precedence when reachable.
DEFAULT_PRICES: dict[str, tuple[float, float]] = {
    "deepseek/deepseek-v4.1-flash": (0.033, 0.08),
    "deepseek/deepseek-v4-pro": (0.428, 0.855),
    "anthropic/claude-opus-5.5": (4.0, 20.0),
    "anthropic/claude-sonnet-5.5": (2.0, 10.0),
}


class BudgetExceeded(Exception):
    """The run or advisory budget is used up; no further LLM calls are allowed."""


@dataclass
class CallRecord:
    model: str
    purpose: str
    advisory: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    cached: bool


@dataclass
class CostTracker:
    """Thread-safe spend accounting with a run-wide and a per-advisory cap."""

    budget_usd: float
    advisory_budget_usd: float
    prices: dict[str, tuple[float, float]] = field(default_factory=lambda: dict(DEFAULT_PRICES))
    records: list[CallRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def spent_usd(self) -> float:
        with self._lock:
            return sum(r.cost_usd for r in self.records)

    def spent_on(self, advisory: str) -> float:
        with self._lock:
            return sum(r.cost_usd for r in self.records if r.advisory == advisory)

    def check(self, advisory: str) -> None:
        """Raise BudgetExceeded if either cap is already reached."""
        if self.spent_usd >= self.budget_usd:
            raise BudgetExceeded(
                f"run budget of ${self.budget_usd:.2f} used up (spent ${self.spent_usd:.4f})"
            )
        if self.spent_on(advisory) >= self.advisory_budget_usd:
            raise BudgetExceeded(
                f"{advisory}: advisory budget of ${self.advisory_budget_usd:.2f} used up"
            )

    def record(
        self,
        model: str,
        purpose: str,
        advisory: str,
        message: AIMessage,
        cached: bool,
    ) -> CallRecord:
        usage: dict[str, Any] = dict(message.usage_metadata or {})
        input_tokens = int(usage.get("input_tokens", 0))
        output_tokens = int(usage.get("output_tokens", 0))
        if cached:
            cost = 0.0
        else:
            # Prefer the amount OpenRouter actually billed (includes provider cache discounts).
            billed = (message.response_metadata.get("token_usage") or {}).get("cost")
            cost = float(billed) if billed is not None else self.estimate(model, usage)
        record = CallRecord(model, purpose, advisory, input_tokens, output_tokens, cost, cached)
        with self._lock:
            self.records.append(record)
        return record

    def estimate(self, model: str, usage: dict[str, Any]) -> float:
        input_price, output_price = self.prices.get(model, (0.0, 0.0))
        if model not in self.prices:
            log.warning("no price known for %s; counting it as $0", model)
        return (
            int(usage.get("input_tokens", 0)) * input_price
            + int(usage.get("output_tokens", 0)) * output_price
        ) / 1_000_000

    def summary(self) -> dict[str, Any]:
        with self._lock:
            records = list(self.records)
        by_model: dict[str, dict[str, float]] = {}
        for r in records:
            m = by_model.setdefault(
                r.model, {"calls": 0, "cached": 0, "input": 0, "output": 0, "usd": 0.0}
            )
            m["calls"] += 1
            m["cached"] += int(r.cached)
            m["input"] += r.input_tokens
            m["output"] += r.output_tokens
            m["usd"] += r.cost_usd
        return {"total_usd": round(sum(r.cost_usd for r in records), 6), "by_model": by_model}


def load_prices(cache: DiskCache | None, api_key: str | None, base_url: str) -> dict[str, Any]:
    """Model prices (USD per million tokens) from OpenRouter, cached for a day; defaults if
    the model list can't be fetched. Listing models is free."""
    prices: dict[str, tuple[float, float]] = dict(DEFAULT_PRICES)
    cached = cache.get(_CACHE_NAMESPACE, _PRICE_CACHE_KEY, _PRICE_TTL_SECONDS) if cache else None
    if cached is None:
        try:
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            resp = httpx.get(f"{base_url}/models", headers=headers, timeout=30)
            resp.raise_for_status()
            cached = {
                m["id"]: [
                    float(m["pricing"]["prompt"]) * 1e6,
                    float(m["pricing"]["completion"]) * 1e6,
                ]
                for m in resp.json().get("data", [])
                if m.get("pricing")
            }
            if cache:
                cache.set(_CACHE_NAMESPACE, _PRICE_CACHE_KEY, cached)
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            log.warning("could not fetch OpenRouter prices, using defaults: %s", exc)
            cached = {}
    for model_id, (input_price, output_price) in cached.items():
        prices[model_id] = (input_price, output_price)
    return prices


class LLM:
    """One chat model with caching and cost accounting.

    SECURITY: prompts carry untrusted advisory text, commit messages and code. The model can
    only act through the read-only tools it is given, and every answer is checked by code
    before it is trusted. With more time: strip or fence instructions found in repo content.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str,
        base_url: str,
        tracker: CostTracker,
        cache: DiskCache | None,
        max_tokens: int = 4096,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self._tracker = tracker
        self._cache = cache
        self._max_tokens = max_tokens
        self._chat = ChatOpenAI(
            model=model,
            api_key=SecretStr(api_key),
            base_url=base_url,
            temperature=0,
            max_completion_tokens=max_tokens,
            timeout=timeout,
            max_retries=3,
            # Ask OpenRouter to report the billed cost with each response.
            extra_body={"usage": {"include": True}},
            default_headers={"X-Title": "advisory-tracer"},
        )

    def invoke(
        self,
        messages: Sequence[BaseMessage],
        *,
        advisory: str,
        purpose: str,
        tools: Sequence[Any] = (),
        force_tool: str | None = None,
    ) -> AIMessage:
        """Call the model (or the cache). `force_tool` makes it answer by calling that tool,
        which is how structured output is requested."""
        tool_schemas = [convert_to_openai_tool(t) for t in tools]
        key = self._cache_key(messages, tool_schemas, force_tool)
        if self._cache is not None:
            hit = self._cache.get(_CACHE_NAMESPACE, key)
            if hit is not None:
                message = messages_from_dict([hit])[0]
                assert isinstance(message, AIMessage)
                self._tracker.record(self.model, purpose, advisory, message, cached=True)
                return message

        self._tracker.check(advisory)
        runnable: Any = self._chat
        if tool_schemas:
            runnable = self._chat.bind_tools(tool_schemas, tool_choice=force_tool)
        message = runnable.invoke(list(messages))
        assert isinstance(message, AIMessage)
        record = self._tracker.record(self.model, purpose, advisory, message, cached=False)
        log.info(
            "%s %s: %d in / %d out tokens, $%.5f",
            self.model,
            purpose,
            record.input_tokens,
            record.output_tokens,
            record.cost_usd,
        )
        if self._cache is not None:
            self._cache.set(_CACHE_NAMESPACE, key, message_to_dict(message))
        return message

    def structured[T: BaseModel](
        self,
        messages: Sequence[BaseMessage],
        schema: type[T],
        *,
        advisory: str,
        purpose: str,
    ) -> T:
        """Ask for an answer matching `schema` (via a forced tool call) and validate it."""
        # Some models (Claude Opus 5.5) reject a forced tool_choice, so the tool is offered and the
        # instruction to call it is part of the prompt.
        message = self.invoke(messages, advisory=advisory, purpose=purpose, tools=[schema])
        calls = [c for c in message.tool_calls if c["name"] == schema.__name__]
        if not calls:
            raise ValueError(f"{self.model} did not return a {schema.__name__}")
        return schema.model_validate(calls[0]["args"])

    def _cache_key(
        self, messages: Sequence[BaseMessage], tool_schemas: list[Any], force_tool: str | None
    ) -> str:
        payload = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "messages": [_request_view(m) for m in messages],
            "tools": tool_schemas,
            "force_tool": force_tool,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _request_view(message: BaseMessage) -> dict[str, Any]:
    """The parts of a message that the model sees. Response metadata (ids, timings) is left out
    so the same conversation always gets the same cache key."""
    view: dict[str, Any] = {"type": message.type, "content": message.content}
    if isinstance(message, AIMessage) and message.tool_calls:
        view["tool_calls"] = [
            {"name": c["name"], "args": c["args"], "id": c.get("id")} for c in message.tool_calls
        ]
    if tool_call_id := getattr(message, "tool_call_id", None):
        view["tool_call_id"] = tool_call_id
    return view
