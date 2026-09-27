"""Shared setup for the examples: live Jev when TYPESAFE_API_KEY is set, otherwise offline."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from jev_firewall import FakeJevClient, Firewall, PolicyEngine, TimeoutDenyApproval
from jev_firewall.audit import AuditLog
from jev_firewall.jev import build_jev_client
from jev_firewall.policy import Policy

ROOT = Path(__file__).resolve().parents[1]


def make_firewall() -> Firewall:
    policy = Policy.from_yaml(ROOT / "policy.example.yaml")
    jev: Any
    if os.environ.get("TYPESAFE_API_KEY"):
        jev = build_jev_client(policy.jev)
        print(f"[jev-firewall] live Jev via {policy.jev.route}")
    else:
        jev = FakeJevClient()
        print("[jev-firewall] TYPESAFE_API_KEY not set: using the offline FakeJevClient (not Jev)")
    audit = AuditLog(Path(tempfile.mkdtemp()) / "audit.jsonl")
    # Unattended examples: held actions are denied instead of prompting.
    return Firewall(PolicyEngine(policy, jev, audit=audit), TimeoutDenyApproval())
