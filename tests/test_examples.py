"""Every minimal example must run offline and block its destructive call."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "name",
    [
        "langgraph_minimal",
        "langchain_minimal",
        "openai_agents_minimal",
        "google_adk_minimal",
        "semantic_kernel_minimal",
    ],
)
def test_example_runs_offline(name: str) -> None:
    env = {k: v for k, v in os.environ.items() if k != "TYPESAFE_API_KEY"}
    r = subprocess.run(
        [sys.executable, str(ROOT / "examples" / f"{name}.py")],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT / "examples",
        timeout=120,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "blocked by jev-firewall" in r.stdout.lower() or "BLOCKED" in r.stdout, r.stdout
