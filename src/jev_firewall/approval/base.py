"""The approval channel interface for held actions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from jev_firewall.verdict import Verdict


@dataclass(frozen=True)
class ApprovalRequest:
    call_id: str
    tool_name: str
    redacted_args: Mapping[str, Any]
    agent_goal: str | None
    verdict: Verdict

    @classmethod
    def from_verdict(cls, v: Verdict) -> ApprovalRequest:
        return cls(v.call_id, v.tool_name, v.redacted_args, v.agent_goal, v)

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tool_name": self.tool_name,
            "tool_args": dict(self.redacted_args),
            "agent_goal": self.agent_goal,
            "reasons": list(self.verdict.reasons),
            "severity": None if self.verdict.assessment is None else self.verdict.assessment.severity.value,
        }


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    resolver: str
    note: str | None = None


@runtime_checkable
class ApprovalChannel(Protocol):
    """Resolves a HOLD. Must never raise for a normal "no"; return `approved=False` instead."""

    async def request(self, req: ApprovalRequest) -> ApprovalResult: ...
