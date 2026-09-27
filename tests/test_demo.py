"""The adversarial demo and suite runner must keep working offline."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytest.importorskip("langgraph")

ROOT = Path(__file__).resolve().parents[1]


def _load(rel: str) -> ModuleType:
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = mod
    spec.loader.exec_module(mod)
    return mod


def test_adversarial_demo_offline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    demo = _load("examples/langgraph_adversarial_demo.py")
    code = demo.main(["--offline", "--audit", str(tmp_path / "a.jsonl")])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "EXECUTED" in out  # benign steps ran
    assert out.count("HARMFUL") == 4
    # Harmful commands never reached the (simulated) tools.
    assert all("rm -rf /" not in args.get("command", "") for _, args in demo.EXECUTED)


def test_suite_runner_hard_layer(tmp_path: Path) -> None:
    runner = _load("benchmarks/run_suites.py")
    assert runner.main(["--layers", "hard", "--out", str(tmp_path)]) == 0
    assert list(tmp_path.glob("*.json"))


def test_hard_marked_cases_are_caught_by_patterns() -> None:
    """Every case tagged `hard: true` in the suites must be caught without Jev."""
    import asyncio

    runner = _load("benchmarks/run_suites.py")
    summary = asyncio.run(runner.run("hard", False, ["destructive", "injected"]))
    import yaml

    tagged = set()
    for name in ("destructive", "injected"):
        data = yaml.safe_load((ROOT / "benchmarks" / "suites" / f"{name}.yaml").read_text(encoding="utf-8"))
        tagged |= {c["id"] for c in data["cases"] if c.get("hard")}
    caught = {c["id"] for c in summary["cases"] if c["correct"]}
    assert tagged <= caught, sorted(tagged - caught)
