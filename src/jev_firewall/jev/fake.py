"""Offline stand-ins for Jev, for tests, CI, and keyless demos.

`FakeJevClient` never touches the network. Its default responder is a crude keyword
heuristic so that demos behave plausibly without a key; it is NOT Jev and none of the
accuracy numbers in this project are measured with it.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

from jev_firewall.errors import JevUnavailable
from jev_firewall.jev.types import ChoiceResult, JevResponse, NoulResult
from jev_firewall.rubric import GOAL_MATCH, IRREVERSIBLE, SEVERITY

Responder = Callable[[Mapping[str, Any], Mapping[str, Mapping[str, Any]]], JevResponse]

_CRITICAL = re.compile(
    r"rm\s+-\w*r\w*f?\s+(/|~|\*|/\*)(\s|$)|mkfs|dd\s+if=.*of=/dev/|drop\s+(database|schema)|"
    r"curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|chmod\s+-R\s+777\s+/|:\(\)\{|"
    r"id_rsa|\.ssh/|/etc/shadow|exfiltrat|disable.*(firewall|mfa|2fa|audit)",
    re.IGNORECASE,
)
_HIGH = re.compile(
    r"\brm\b|delete|drop\s+table|truncate|send_?(email|message)|transfer|refund|wire|payment|"
    r"deploy|push\s+--force|force-push|publish|shutdown|reboot|kill\b|revoke|grant|chmod|chown",
    re.IGNORECASE,
)
_MODERATE = re.compile(r"write|edit|create|update|insert|mkdir|mv\b|cp\b|patch|append", re.IGNORECASE)
_IRREVERSIBLE = re.compile(
    r"\brm\b|delete|drop|truncate|send|transfer|refund|wire|payment|publish|mkfs|dd\s+if|shred|"
    r"push\s+--force|curl[^|]*\|",
    re.IGNORECASE,
)
_HOST = re.compile(r"(?:https?://|@)([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)


def _foreign_hosts(action_text: str, goal: str) -> set[str]:
    """Domains the action reaches (URLs, email recipients) that the goal never mentions."""
    goal_l = goal.lower()
    return {h.lower() for h in _HOST.findall(action_text) if h.lower() not in goal_l}


def heuristic_responder(state: Mapping[str, Any], questions: Mapping[str, Mapping[str, Any]]) -> JevResponse:
    action = state.get("proposed_action", {})
    text = json.dumps(action, ensure_ascii=False)
    if _CRITICAL.search(text):
        tier, probs = "critical_danger", {"critical_danger": 0.8, "high_risk": 0.2}
    elif _HIGH.search(text):
        tier, probs = "high_risk", {"high_risk": 0.75, "moderate_risk": 0.2, "critical_danger": 0.05}
    elif _MODERATE.search(text):
        tier, probs = "moderate_risk", {"moderate_risk": 0.7, "low_risk": 0.25, "high_risk": 0.05}
    else:
        tier, probs = "low_risk", {"low_risk": 0.85, "moderate_risk": 0.15}
    full = {k: probs.get(k, 0.0) for k in ("low_risk", "moderate_risk", "high_risk", "critical_danger")}
    nouls = {IRREVERSIBLE: NoulResult(0.9 if _IRREVERSIBLE.search(text) else 0.1)}
    if GOAL_MATCH in questions:
        foreign = _foreign_hosts(text, str(state.get("agent_goal", "")))
        nouls[GOAL_MATCH] = NoulResult(0.2 if foreign else 0.8)
    return JevResponse(
        model="fake-heuristic",
        choices={SEVERITY: ChoiceResult(tier, full, confidence=max(full.values()))},
        nouls=nouls,
        input_tokens=len(json.dumps(state)) // 4,
        request_id=None,
    )


def fixed_responder(
    *,
    severity: str = "low_risk",
    irreversible: float = 0.1,
    goal_match: float = 0.9,
    confidence: float = 0.9,
) -> Responder:
    """Always return the same assessment. Useful for unit-testing decision rules."""

    def respond(state: Mapping[str, Any], questions: Mapping[str, Mapping[str, Any]]) -> JevResponse:
        nouls = {IRREVERSIBLE: NoulResult(irreversible)}
        if GOAL_MATCH in questions:
            nouls[GOAL_MATCH] = NoulResult(goal_match)
        return JevResponse(
            model="fake-fixed",
            choices={SEVERITY: ChoiceResult(severity, {severity: 1.0}, confidence)},
            nouls=nouls,
            input_tokens=100,
        )

    return respond


class FakeJevClient:
    """In-memory `JevClient`. Records every request so tests can assert on what was sent."""

    def __init__(
        self,
        responder: Responder = heuristic_responder,
        *,
        latency_s: float = 0.0,
        fail: bool | Exception = False,
    ) -> None:
        self.responder = responder
        self.latency_s = latency_s
        self.fail = fail
        self.requests: list[tuple[dict[str, Any], dict[str, Any]]] = []

    async def system_one(
        self, state: Mapping[str, Any], questions: Mapping[str, Mapping[str, Any]]
    ) -> JevResponse:
        self.requests.append((json.loads(json.dumps(state)), json.loads(json.dumps(questions))))
        if self.latency_s:
            await asyncio.sleep(self.latency_s)
        if isinstance(self.fail, Exception):
            raise self.fail
        if self.fail:
            raise JevUnavailable("FakeJevClient configured to fail")
        return self.responder(state, questions)

    async def aclose(self) -> None:
        return None
