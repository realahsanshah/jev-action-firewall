from __future__ import annotations

import copy
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from jev_firewall import AuditLog, FakeJevClient, Firewall, Policy, PolicyEngine
from jev_firewall.approval import ApprovalRequest, ApprovalResult
from jev_firewall.jev.fake import Responder, fixed_responder

ROOT = Path(__file__).resolve().parents[1]

BASE_POLICY: dict[str, Any] = {
    "version": 1,
    "fail_mode": "closed",
    "jev": {"route": "direct", "timeout_s": 0.5, "max_retries": 0},
    "defaults": {
        "thresholds": {
            "low_risk": "allow",
            "moderate_risk": "allow",
            "high_risk": "hold",
            "critical_danger": "deny",
        },
        "irreversible_threshold": 0.5,
        "goal_match_threshold": 0.5,
        "min_confidence": 0.5,
        "hard_patterns": [
            {"description": "rm root", "pattern": r"\brm\s+-rf\s+/(\s|$)", "floor": "deny"},
            {"description": "force push", "pattern": r"git\s+push\s+--force", "floor": "hold"},
        ],
    },
    "tools": {
        "read_*": {"action": "allow"},
        "read_secrets": {"action": "deny"},
        "admin_*": {"action": "hold"},
        "notes_*": {"allow_irreversible": True},
        "flaky_tool": {"fail_mode": "open"},
    },
}


def make_policy(**overrides: Any) -> Policy:
    raw = copy.deepcopy(BASE_POLICY)
    for key, value in overrides.items():
        raw[key] = value
    return Policy.from_mapping(raw)


class RecordingApproval:
    def __init__(self, approved: bool, resolver: str = "test") -> None:
        self.approved = approved
        self.resolver = resolver
        self.requests: list[ApprovalRequest] = []

    async def request(self, req: ApprovalRequest) -> ApprovalResult:
        self.requests.append(req)
        return ApprovalResult(self.approved, self.resolver)


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def make_engine(audit: AuditLog) -> Iterator[Any]:
    engines: list[PolicyEngine] = []

    def factory(
        responder: Responder | None = None, *, policy: Policy | None = None, **fake_kwargs: Any
    ) -> tuple[PolicyEngine, FakeJevClient]:
        fake = FakeJevClient(responder or fixed_responder(), **fake_kwargs)
        engine = PolicyEngine(policy or make_policy(), fake, audit=audit)
        engines.append(engine)
        return engine, fake

    yield factory
    for e in engines:
        e.close()


@pytest.fixture
def make_firewall(make_engine: Any) -> Any:
    def factory(
        responder: Responder | None = None, *, approved: bool = False, **kwargs: Any
    ) -> tuple[Firewall, FakeJevClient, RecordingApproval]:
        engine, fake = make_engine(responder, **kwargs)
        approval = RecordingApproval(approved)
        return Firewall(engine, approval), fake, approval

    return factory
