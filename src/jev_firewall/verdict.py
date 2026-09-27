"""Typed values that flow through the firewall: tool calls, Jev assessments, verdicts."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Literal


class Decision(StrEnum):
    """What the firewall does with a proposed action. Ordered: ALLOW < HOLD < DENY."""

    ALLOW = "allow"
    HOLD = "hold"
    DENY = "deny"

    @property
    def rank(self) -> int:
        return _RANK[self]

    def at_least(self, other: Decision) -> Decision:
        """Return the stricter of the two decisions. Rules only ever escalate."""
        return self if self.rank >= other.rank else other


_RANK = {Decision.ALLOW: 0, Decision.HOLD: 1, Decision.DENY: 2}


class SeverityTier(StrEnum):
    """Options of the `severity` Choice question, in increasing order of danger."""

    LOW_RISK = "low_risk"
    MODERATE_RISK = "moderate_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_DANGER = "critical_danger"


VerdictSource = Literal["jev", "static_rule", "hard_pattern", "fail_open", "fail_closed"]


@dataclass(frozen=True)
class ToolCall:
    """A proposed tool invocation, as handed to the firewall by an adapter."""

    tool_name: str
    tool_args: Mapping[str, Any]
    agent_goal: str | None = None
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    framework: str | None = None


@dataclass(frozen=True)
class JevAssessment:
    """Jev's answers to the default rubric, normalized away from any transport."""

    severity: SeverityTier
    severity_probabilities: Mapping[str, float]
    severity_confidence: float
    irreversible: float
    goal_match: float | None
    model: str
    input_tokens: int | None
    request_id: str | None
    latency_ms: float


@dataclass(frozen=True)
class Verdict:
    """The firewall's decision about one tool call, with everything needed to audit it."""

    decision: Decision
    call_id: str
    tool_name: str
    redacted_args: Mapping[str, Any]
    agent_goal: str | None
    source: VerdictSource
    reasons: tuple[str, ...]
    assessment: JevAssessment | None
    matched_rule: str | None
    latency_ms: float
    error: str | None = None

    @property
    def confidence(self) -> float | None:
        """Confidence of the severity Choice. Jev's Noul answers carry no confidence."""
        return None if self.assessment is None else self.assessment.severity_confidence

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        if self.assessment is not None:
            data["assessment"]["severity"] = self.assessment.severity.value
        data["reasons"] = list(self.reasons)
        return data
