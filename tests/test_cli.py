from pathlib import Path
from typing import Any

import pytest
import respx

from advisory_tracer import cli

API = "https://api.github.com"


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path / "output"))
    return tmp_path


def test_missing_token_is_a_config_error(
    env: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN")

    assert cli.main(["fetch"]) == cli.EXIT_CONFIG
    assert "GITHUB_TOKEN is not set" in caplog.text


def test_invalid_ghsa_id_is_rejected(env: Path) -> None:
    assert cli.main(["fetch", "--ids", "not-an-id"]) == cli.EXIT_CONFIG


@respx.mock
def test_bad_token_gives_clear_error(env: Path, caplog: pytest.LogCaptureFixture) -> None:
    respx.get(f"{API}/advisories").respond(401, json={"message": "Bad credentials"})

    assert cli.main(["fetch", "--limit", "1"]) == cli.EXIT_CONFIG
    assert "rejected the token" in caplog.text


@respx.mock
def test_fetch_writes_files(env: Path, advisory_payload: dict[str, Any]) -> None:
    respx.get(f"{API}/advisories/GHSA-2222-3333-4444").respond(json=advisory_payload)

    assert cli.main(["fetch", "--ids", "GHSA-2222-3333-4444"]) == cli.EXIT_OK
    assert (env / "output" / "advisories" / "GHSA-2222-3333-4444.json").exists()
