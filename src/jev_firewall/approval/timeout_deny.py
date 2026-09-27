"""Reject held actions that are not approved in time."""

from __future__ import annotations

import asyncio

from jev_firewall.approval.base import ApprovalChannel, ApprovalRequest, ApprovalResult


class TimeoutDenyApproval:
    """Wraps another channel and rejects if it has not approved within `timeout_s`.

    With no inner channel it rejects every held action immediately, which is the right choice
    for unattended agents: HOLD degrades to DENY instead of hanging.
    """

    def __init__(self, inner: ApprovalChannel | None = None, *, timeout_s: float = 0.0) -> None:
        self.inner = inner
        self.timeout_s = timeout_s

    async def request(self, req: ApprovalRequest) -> ApprovalResult:
        if self.inner is None:
            return ApprovalResult(False, "auto:deny", "no approver configured; held actions are denied")
        try:
            async with asyncio.timeout(self.timeout_s):
                return await self.inner.request(req)
        except TimeoutError:
            return ApprovalResult(False, "auto:timeout", f"not approved within {self.timeout_s}s")
