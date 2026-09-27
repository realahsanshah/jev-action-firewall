"""`jev-firewall` command line: validate a policy, evaluate one action, summarize an audit log."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from jev_firewall.audit import read_audit
from jev_firewall.engine import PolicyEngine
from jev_firewall.errors import FirewallError
from jev_firewall.jev.fake import FakeJevClient
from jev_firewall.jev.types import JevClient
from jev_firewall.policy import Policy, RiskThresholds
from jev_firewall.verdict import ToolCall


def _check(args: argparse.Namespace) -> int:
    policy = Policy.from_yaml(args.policy)
    rt = RiskThresholds(policy)
    print(f"OK: {args.policy}")
    print(
        f"  fail_mode: {policy.fail_mode}   jev.route: {policy.jev.route}   timeout_s: {policy.jev.timeout_s}"
    )
    print(f"  tool rules: {len(policy.tools)}   default hard patterns: {len(policy.defaults.hard_patterns)}")
    for name in args.tool or []:
        r = rt.resolve(name)
        th = {k.value: v.value for k, v in r.thresholds.items()}
        print(f"  {name}: rule={r.matched or '(defaults)'} action={r.action} fail_mode={r.fail_mode} {th}")
    return 0


def _eval(args: argparse.Namespace) -> int:
    policy = Policy.from_yaml(args.policy)
    policy = Policy.from_mapping({**policy.model_dump(mode="json"), "audit": None, "approval": None})
    jev: JevClient | None = FakeJevClient() if args.offline else None
    with PolicyEngine.from_policy(policy, jev=jev) as engine:
        v = engine.evaluate(ToolCall(args.tool, json.loads(args.args), args.goal))
    out = v.to_dict()
    if args.offline:
        out["note"] = "offline FakeJevClient: not a Jev answer"
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return {"allow": 0, "hold": 10, "deny": 20}[v.decision.value]


def _audit(args: argparse.Namespace) -> int:
    verdicts = [r for r in read_audit(args.path) if r["event"] == "verdict"]
    if not verdicts:
        print("no verdicts recorded")
        return 0
    by = Counter(r["decision"] for r in verdicts)
    src = Counter(r["source"] for r in verdicts)
    lat = sorted(r["latency_ms"] for r in verdicts)
    print(f"{len(verdicts)} decisions: " + ", ".join(f"{k}={by[k]}" for k in ("allow", "hold", "deny")))
    print("sources: " + ", ".join(f"{k}={v}" for k, v in src.most_common()))
    p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))]
    print(f"latency ms p50={lat[len(lat) // 2]:.1f} p95={p95:.1f}")
    tools = Counter((r["tool_name"], r["decision"]) for r in verdicts if r["decision"] != "allow")
    for (tool, decision), n in tools.most_common(args.top):
        print(f"  {decision:5} {n:4}  {tool}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="jev-firewall", description="Runtime action firewall for AI agents.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="validate a policy file")
    c.add_argument("policy", type=Path)
    c.add_argument("--tool", action="append", help="show the effective rule for this tool name")
    c.set_defaults(fn=_check)

    e = sub.add_parser("eval", help="evaluate one proposed action (exit 0 allow, 10 hold, 20 deny)")
    e.add_argument("policy", type=Path)
    e.add_argument("--tool", required=True)
    e.add_argument("--args", default="{}", help="tool arguments as JSON")
    e.add_argument("--goal", default=None, help="one-line summary of the agent's task")
    e.add_argument("--offline", action="store_true", help="use the keyword FakeJevClient instead of Jev")
    e.set_defaults(fn=_eval)

    a = sub.add_parser("audit", help="summarize an audit log")
    a.add_argument("path", type=Path)
    a.add_argument("--top", type=int, default=10)
    a.set_defaults(fn=_audit)

    args = ap.parse_args(argv)
    try:
        return int(args.fn(args))
    except (FirewallError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
