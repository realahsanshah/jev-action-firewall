"""Run the seeded suites through the firewall and report FN/FP, latency, tokens and cost.

    uv run python benchmarks/run_suites.py                 # live Jev (needs TYPESAFE_API_KEY)
    uv run python benchmarks/run_suites.py --layers jev    # Jev alone, hard patterns removed
    uv run python benchmarks/run_suites.py --offline       # FakeJevClient smoke run (NOT Jev)

Results are written to benchmarks/results/<timestamp>-<layers>.{json,md}. Only live runs
produce numbers worth reporting; offline runs are labelled as such in every output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml

from jev_firewall import FakeJevClient, PolicyEngine, ToolCall
from jev_firewall.jev import build_jev_client
from jev_firewall.policy import Policy

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PRICE_PER_MTOK = 0.042  # USD per million input tokens, docs.typesafe.ai/models (jev-1.13)

Layers = Literal["both", "jev", "hard"]


@dataclass
class CaseResult:
    suite: str
    id: str
    tool: str
    expect: str
    decision: str
    source: str
    correct: bool
    latency_ms: float
    jev_latency_ms: float | None
    input_tokens: int | None
    severity: str | None
    irreversible: float | None
    goal_match: float | None
    confidence: float | None
    reasons: list[str]
    error: str | None


def load_suites(names: Sequence[str]) -> list[tuple[str, str, dict[str, Any]]]:
    cases = []
    for name in names:
        data = yaml.safe_load((HERE / "suites" / f"{name}.yaml").read_text(encoding="utf-8"))
        for c in data["cases"]:
            cases.append((data["suite"], data["expect"], c))
    return cases


def build_policy(layers: Layers) -> Policy:
    raw = yaml.safe_load((ROOT / "policy.example.yaml").read_text(encoding="utf-8"))
    raw["approval"] = None
    raw["audit"] = None
    if layers == "jev":
        raw["defaults"]["hard_patterns"] = []
    return Policy.from_mapping(raw)


def pct(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


async def run(layers: Layers, offline: bool, suites: Sequence[str]) -> dict[str, Any]:
    policy = build_policy(layers)
    if offline:
        jev: Any = FakeJevClient()
        label = "offline FakeJevClient (keyword heuristic, NOT Jev)"
    elif layers == "hard":
        jev = FakeJevClient(fail=True)  # every Jev call "fails"; fail_mode decides
        policy = Policy.from_mapping({**policy.model_dump(mode="json"), "fail_mode": "open"})
        label = "hard patterns only (Jev disabled, fail_mode=open)"
    else:
        jev = build_jev_client(policy.jev)
        label = f"live Jev via {policy.jev.route} ({policy.jev.model or 'route default model'})"

    engine = PolicyEngine(policy, jev)
    results: list[CaseResult] = []
    warmup_ms: float | None = None
    try:
        if not offline and layers != "hard":
            t = time.perf_counter()
            await engine.aevaluate(ToolCall("terminal", {"command": "echo warmup"}, "warm up the connection"))
            warmup_ms = (time.perf_counter() - t) * 1000

        for suite, expect, c in load_suites(suites):
            v = await engine.aevaluate(ToolCall(c["tool"], c["args"], c.get("goal")))
            a = v.assessment
            blocked = v.decision.value in ("hold", "deny")
            results.append(
                CaseResult(
                    suite=suite,
                    id=c["id"],
                    tool=c["tool"],
                    expect=expect,
                    decision=v.decision.value,
                    source=v.source,
                    correct=blocked if expect == "block" else not blocked,
                    latency_ms=v.latency_ms,
                    jev_latency_ms=None if a is None else round(a.latency_ms, 3),
                    input_tokens=None if a is None else a.input_tokens,
                    severity=None if a is None else a.severity.value,
                    irreversible=None if a is None else a.irreversible,
                    goal_match=None if a is None else a.goal_match,
                    confidence=None if a is None else a.severity_confidence,
                    reasons=list(v.reasons),
                    error=v.error,
                )
            )
    finally:
        await engine.aclose()

    return summarize(results, label=label, layers=layers, offline=offline, warmup_ms=warmup_ms)


def summarize(
    results: list[CaseResult], *, label: str, layers: str, offline: bool, warmup_ms: float | None
) -> dict[str, Any]:
    by_suite: dict[str, dict[str, Any]] = {}
    for suite in sorted({r.suite for r in results}):
        rs = [r for r in results if r.suite == suite]
        wrong = [r.id for r in rs if not r.correct]
        by_suite[suite] = {"n": len(rs), "wrong": len(wrong), "wrong_ids": wrong}
    harmful = [r for r in results if r.expect == "block"]
    benign = [r for r in results if r.expect == "allow"]
    jev_calls = [r for r in results if r.jev_latency_ms is not None]
    lat = [r.latency_ms for r in jev_calls]
    jlat = [r.jev_latency_ms for r in jev_calls if r.jev_latency_ms is not None]
    tokens = [r.input_tokens for r in jev_calls if r.input_tokens is not None]
    errors = [r for r in results if r.error]
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "mode": label,
        "layers": layers,
        "offline": offline,
        "false_negatives": sum(not r.correct for r in harmful),
        "harmful_total": len(harmful),
        "false_positives": sum(not r.correct for r in benign),
        "benign_total": len(benign),
        "fp_rate": (sum(not r.correct for r in benign) / len(benign)) if benign else None,
        "suites": by_suite,
        "jev_calls": len(jev_calls),
        "jev_errors": len(errors),
        "warmup_ms": None if warmup_ms is None else round(warmup_ms, 1),
        "latency_ms_engine": _dist(lat),
        "latency_ms_jev_roundtrip": _dist(jlat),
        "input_tokens": _dist([float(t) for t in tokens]),
        "cost_usd_per_decision_mean": (statistics.mean(tokens) * PRICE_PER_MTOK / 1e6) if tokens else None,
        "cases": [asdict(r) for r in results],
    }


def _dist(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 2),
        "p50": round(pct(values, 0.50), 2),
        "p95": round(pct(values, 0.95), 2),
        "p99": round(pct(values, 0.99), 2),
        "max": round(max(values), 2),
    }


def to_markdown(s: dict[str, Any]) -> str:
    lines = [
        f"# Suite results: {s['mode']}",
        "",
        f"Generated {s['generated_at']}.",
        "",
        "| metric | value |",
        "|---|---|",
        f"| false negatives | {s['false_negatives']} / {s['harmful_total']} |",
        f"| false positives | {s['false_positives']} / {s['benign_total']}"
        + (f" ({s['fp_rate']:.1%})" if s["fp_rate"] is not None else "")
        + " |",
        f"| Jev calls / errors | {s['jev_calls']} / {s['jev_errors']} |",
    ]
    for key, name in (
        ("latency_ms_engine", "engine latency ms"),
        ("latency_ms_jev_roundtrip", "Jev round trip ms"),
    ):
        d = s[key]
        if d:
            lines.append(
                f"| {name} p50 / p95 / p99 / max | {d['p50']} / {d['p95']} / {d['p99']} / {d['max']} |"
            )
    if s["input_tokens"]:
        lines.append(
            f"| input tokens mean / max | {s['input_tokens']['mean']} / {s['input_tokens']['max']} |"
        )
    if s["cost_usd_per_decision_mean"] is not None:
        lines.append(f"| cost per decision (mean) | ${s['cost_usd_per_decision_mean']:.8f} |")
    lines += [
        "",
        "## Misclassified",
        "",
        "| suite | id | tool | decision | source | reasons |",
        "|---|---|---|---|---|---|",
    ]
    for c in s["cases"]:
        if not c["correct"]:
            lines.append(
                f"| {c['suite']} | {c['id']} | {c['tool']} | {c['decision']} | {c['source']} | "
                f"{'; '.join(c['reasons'])} |"
            )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--layers", choices=["both", "jev", "hard"], default="both")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--suites", nargs="+", default=["destructive", "injected", "benign"])
    ap.add_argument("--out", type=Path, default=HERE / "results")
    args = ap.parse_args(argv)

    if not args.offline and args.layers != "hard" and not os.environ.get("TYPESAFE_API_KEY"):
        print("TYPESAFE_API_KEY is not set; use --offline for a smoke run (numbers are not Jev's).")
        return 2

    summary = asyncio.run(run(args.layers, args.offline, args.suites))
    args.out.mkdir(parents=True, exist_ok=True)
    stem = f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{'offline' if args.offline else args.layers}"
    (args.out / f"{stem}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    md = to_markdown(summary)
    (args.out / f"{stem}.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"written: {args.out / stem}.json/.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
