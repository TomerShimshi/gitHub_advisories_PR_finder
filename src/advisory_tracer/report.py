"""YAML output."""

from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import BaseModel


def write_yaml(items: Sequence[BaseModel], path: Path) -> Path:
    """Write models as a YAML list. safe_dump never emits Python object tags."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [item.model_dump(mode="json", exclude_none=False) for item in items]
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=100)
    return path
