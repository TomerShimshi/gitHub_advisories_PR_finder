import copy
import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def advisory_payload() -> dict[str, Any]:
    """A global advisory payload shaped like GET /advisories/{ghsa_id} (hand-written sample)."""
    data: dict[str, Any] = json.loads((FIXTURES / "advisory.json").read_text(encoding="utf-8"))
    return copy.deepcopy(data)


@pytest.fixture
def no_sleep() -> Any:
    calls: list[float] = []

    def sleep(seconds: float) -> None:
        calls.append(seconds)

    sleep.calls = calls  # type: ignore[attr-defined]
    return sleep
