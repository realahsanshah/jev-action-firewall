"""`PolicyEngine`: turns a proposed tool call into a `Verdict`.

Order of evaluation (each step can only make the decision stricter):

1. Resolve the tool's rule (exact name, then most specific glob, then defaults).
2. Hard patterns on raw args set a floor. A DENY floor or a static `deny` rule ends here.
3. Static `allow`/`hold` rules skip Jev.
4. Ask Jev the rubric; map `severity` through the tool's thresholds.
5. Irreversible and not allowlisted: ALLOW becomes HOLD.
6. `matches_stated_goal` below threshold: at least HOLD.
7. Severity confidence below `min_confidence`: at least HOLD.

If Jev fails for any reason, the rule's explicit `fail_mode` decides: `open` allows (still
respecting any hard-pattern floor), `closed` denies.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self

import httpx2

from jev_firewall._runtime import LoopThread
from jev_firewall.audit import AuditLog
from jev_firewall.errors import JevUnavailable
from jev_firewall.jev import build_jev_client
from jev_firewall.jev.types import JevClient
from jev_firewall.policy import Policy, ResolvedRule, RiskThresholds
from jev_firewall.redact import Redactor, flatten_strings
from jev_firewall.rubric import build_questions, build_state, parse_assessment
from jev_firewall.verdict import Decision, JevAssessment, ToolCall, Verdict, VerdictSource


class PolicyEngine:
    def __init__(
        self,
        policy: Policy,
        jev: JevClient,
        *,
        audit: AuditLog | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self.policy = policy
        self.thresholds = RiskThresholds(policy)
        self.jev = jev
        self.audit = audit
        self.redactor = redactor or Redactor(policy.redaction)
        self._loop = LoopThread()

    @classmethod
    def from_policy(
        cls,
        policy: Policy,
        *,
        jev: JevClient | None = None,
        audit: AuditLog | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> Self:
        if jev is None:
            jev = build_jev_client(policy.jev, transport=transport)
        if audit is None and policy.audit is not None:
            audit = AuditLog(policy.audit.path, fsync=policy.audit.fsync)
        return cls(policy, jev, audit=audit)

    @classmethod
    def from_yaml(
        cls, path: str | Path, *, jev: JevClient | None = None, audit: AuditLog | None = None
    ) -> Self:
        return cls.from_policy(Policy.from_yaml(path), jev=jev, audit=audit)

    # -- public API ------------------------------------------------------------------------

    async def aevaluate(self, call: ToolCall) -> Verdict:
        return await self._loop.arun(self._evaluate(call))

    def evaluate(self, call: ToolCall) -> Verdict:
        return self._loop.run(self._evaluate(call))

    async def aclose(self) -> None:
        await self._loop.arun(self.jev.aclose())
        self._loop.close()
        if self.audit is not None:
            self.audit.close()

    def close(self) -> None:
        self._loop.run(self.jev.aclose())
        self._loop.close()
        if self.audit is not None:
            self.audit.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, et: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.aclose()

    # -- decision logic --------------------------------------------------------------------

    async def _evaluate(self, call: ToolCall) -> Verdict:
        start = time.perf_counter()
        rule = self.thresholds.resolve(call.tool_name)
        redacted_args, _ = self.redactor.redact_args(call.tool_args)
        goal = self.redactor.redact_goal(call.agent_goal)
        floor, reasons_t = rule.hard_floor(f"{call.tool_name}\n{flatten_strings(call.tool_args)}")
        reasons = list(reasons_t)

        def finish(
            decision: Decision,
            source: VerdictSource,
            assessment: JevAssessment | None = None,
            error: str | None = None,
        ) -> Verdict:
            v = Verdict(
                decision=decision,
                call_id=call.call_id,
                tool_name=call.tool_name,
                redacted_args=redacted_args,
                agent_goal=goal,
                source=source,
                reasons=tuple(reasons),
                assessment=assessment,
                matched_rule=rule.matched,
                latency_ms=round((time.perf_counter() - start) * 1000, 3),
                error=error,
            )
            if self.audit is not None:
                self.audit.verdict(v)
            return v

        if rule.action == "deny":
            reasons.append(f"rule:{rule.matched}->deny")
            return finish(Decision.DENY, "static_rule")
        if floor is Decision.DENY:
            return finish(Decision.DENY, "hard_pattern")
        if rule.action in ("allow", "hold"):
            static = Decision(rule.action)
            reasons.append(f"rule:{rule.matched}->{static.value}")
            if floor is not None and floor.rank > static.rank:
                return finish(floor, "hard_pattern")
            return finish(static, "static_rule")

        include_goal = goal is not None
        if not include_goal:
            reasons.append("no_agent_goal:goal_check_skipped")
        state = build_state(call.tool_name, redacted_args, goal)
        questions = build_questions(include_goal=include_goal)
        try:
            async with asyncio.timeout(self.policy.jev.timeout_s):
                resp = await self.jev.system_one(state, questions)
            assessment = parse_assessment(resp, include_goal=include_goal)
        except Exception as exc:  # any Jev failure goes through the explicit fail_mode
            err = "timeout" if isinstance(exc, TimeoutError) else f"{type(exc).__name__}: {exc}"
            return self._fail(rule, floor, reasons, finish, err, exc)

        return finish(self._decide(rule, floor, assessment, reasons), "jev", assessment)

    @staticmethod
    def _decide(rule: ResolvedRule, floor: Decision | None, a: JevAssessment, reasons: list[str]) -> Decision:
        d = rule.thresholds[a.severity]
        reasons.append(f"severity:{a.severity.value}->{d.value}")
        if floor is not None:
            d = d.at_least(floor)
        if a.irreversible >= rule.irreversible_threshold:
            if rule.allow_irreversible:
                reasons.append(f"irreversible:{a.irreversible:.2f}:allowlisted")
            elif d is Decision.ALLOW:
                d = Decision.HOLD
                reasons.append(f"irreversible:{a.irreversible:.2f}->hold")
        if a.goal_match is not None and a.goal_match < rule.goal_match_threshold:
            d = d.at_least(Decision.HOLD)
            reasons.append(f"goal_mismatch:{a.goal_match:.2f}->hold")
        if a.severity_confidence < rule.min_confidence:
            d = d.at_least(Decision.HOLD)
            reasons.append(f"low_confidence:{a.severity_confidence:.2f}->hold")
        return d

    @staticmethod
    def _fail(
        rule: ResolvedRule,
        floor: Decision | None,
        reasons: list[str],
        finish: _Finish,
        err: str,
        exc: Exception,
    ) -> Verdict:
        if not isinstance(exc, (JevUnavailable, TimeoutError)):
            err = f"unexpected client error: {err}"
        if rule.fail_mode == "open":
            reasons.append("jev_unavailable:fail_open")
            d = Decision.ALLOW if floor is None else floor
            return finish(d, "fail_open", None, err)
        reasons.append("jev_unavailable:fail_closed")
        return finish(Decision.DENY, "fail_closed", None, err)


class _Finish(Protocol):  # type of the `finish` closure in `_evaluate`
    def __call__(
        self,
        decision: Decision,
        source: VerdictSource,
        assessment: JevAssessment | None = None,
        error: str | None = None,
    ) -> Verdict: ...
