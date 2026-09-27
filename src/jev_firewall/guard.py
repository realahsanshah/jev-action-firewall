"""`Firewall`: the one protocol every framework adapter uses.

    evaluate -> DENY: raise ActionBlocked
             -> HOLD: await the approval channel; rejected: raise ActionBlocked
             -> ALLOW (or approved HOLD): execute the original tool

Adapters translate their framework's hook into a `ToolCall` and call `check`/`acheck`
(hooks that only get to veto) or `guard`/`aguard` (hooks that wrap execution). They hold no
policy logic, so adding one never touches this package.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal, Self, TypeVar

from jev_firewall._runtime import run_sync
from jev_firewall.approval import ApprovalChannel, ApprovalRequest, ApprovalResult, build_approval
from jev_firewall.audit import AuditLog
from jev_firewall.engine import PolicyEngine
from jev_firewall.errors import ActionBlocked
from jev_firewall.jev.types import JevClient
from jev_firewall.verdict import Decision, ToolCall, Verdict

T = TypeVar("T")


class Firewall:
    def __init__(self, engine: PolicyEngine, approval: ApprovalChannel | None = None) -> None:
        self.engine = engine
        self.approval = approval if approval is not None else build_approval(engine.policy.approval)

    @classmethod
    def from_yaml(
        cls,
        path: str | Path,
        *,
        jev: JevClient | None = None,
        approval: ApprovalChannel | None = None,
        audit: AuditLog | None = None,
    ) -> Self:
        return cls(PolicyEngine.from_yaml(path, jev=jev, audit=audit), approval)

    @property
    def audit(self) -> AuditLog | None:
        return self.engine.audit

    # -- veto-style hooks ------------------------------------------------------------------

    async def acheck(self, call: ToolCall) -> Verdict:
        """Return the verdict if the call may proceed, else raise `ActionBlocked`."""
        return await self.aresolve(await self.engine.aevaluate(call))

    def check(self, call: ToolCall) -> Verdict:
        return self.resolve(self.engine.evaluate(call))

    async def aresolve(self, verdict: Verdict) -> Verdict:
        """Enforce an existing verdict: raise on DENY, run approval on HOLD."""
        if verdict.decision is Decision.HOLD:
            start = time.perf_counter()
            result = await self.approval.request(ApprovalRequest.from_verdict(verdict))
            return self._after_approval(verdict, result, start)
        return self._after_verdict(verdict)

    def resolve(self, verdict: Verdict) -> Verdict:
        if verdict.decision is Decision.HOLD:
            start = time.perf_counter()
            # run_sync keeps the caller's contextvars (LangGraph interrupt() needs them).
            result = run_sync(self.approval.request(ApprovalRequest.from_verdict(verdict)))
            return self._after_approval(verdict, result, start)
        return self._after_verdict(verdict)

    # -- wrap-style hooks ------------------------------------------------------------------

    async def aguard(self, call: ToolCall, execute: Callable[[], Awaitable[T]]) -> T:
        await self.acheck(call)
        return await self.aguard_executed(call, execute)

    def guard(self, call: ToolCall, execute: Callable[[], T]) -> T:
        self.check(call)
        return self.guard_executed(call, execute)

    async def aguard_executed(self, call: ToolCall, execute: Callable[[], Awaitable[T]]) -> T:
        """Run an already-cleared call and audit its outcome."""
        try:
            result = await execute()
        except BaseException as exc:
            self.record_outcome(call.call_id, "error", f"{type(exc).__name__}: {exc}")
            raise
        self.record_outcome(call.call_id, "executed")
        return result

    def guard_executed(self, call: ToolCall, execute: Callable[[], T]) -> T:
        try:
            result = execute()
        except BaseException as exc:
            self.record_outcome(call.call_id, "error", f"{type(exc).__name__}: {exc}")
            raise
        self.record_outcome(call.call_id, "executed")
        return result

    def record_outcome(
        self, call_id: str, status: Literal["executed", "blocked", "error"], detail: str | None = None
    ) -> None:
        if self.audit is not None:
            self.audit.outcome(call_id, status=status, detail=detail)

    # -- internals -------------------------------------------------------------------------

    def _after_verdict(self, verdict: Verdict) -> Verdict:
        if verdict.decision is Decision.DENY:
            self.record_outcome(verdict.call_id, "blocked", "denied")
            raise ActionBlocked(verdict)
        return verdict

    def _after_approval(self, verdict: Verdict, result: ApprovalResult, start: float) -> Verdict:
        if self.audit is not None:
            self.audit.approval(
                verdict.call_id,
                approved=result.approved,
                resolver=result.resolver,
                note=result.note,
                wait_ms=(time.perf_counter() - start) * 1000,
            )
        if not result.approved:
            self.record_outcome(verdict.call_id, "blocked", f"rejected by {result.resolver}")
            raise ActionBlocked(verdict, result)
        return verdict

    def close(self) -> None:
        self.engine.close()

    async def aclose(self) -> None:
        await self.engine.aclose()
