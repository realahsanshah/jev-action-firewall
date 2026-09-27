"""Exceptions raised by the firewall."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jev_firewall.approval.base import ApprovalResult
    from jev_firewall.verdict import Verdict


class FirewallError(Exception):
    """Base class for jev-firewall errors."""


class PolicyConfigError(FirewallError):
    """The policy file or engine configuration is invalid."""


class JevUnavailable(FirewallError):
    """Jev could not produce a usable answer (timeout, HTTP error, malformed response)."""


class ActionBlocked(FirewallError):
    """Raised by adapters instead of executing a tool the firewall did not allow.

    `verdict.decision` is DENY for outright denials, or HOLD when a human (or a timeout)
    rejected a held action; `approval` is set in the second case.
    """

    def __init__(self, verdict: Verdict, approval: ApprovalResult | None = None) -> None:
        self.verdict = verdict
        self.approval = approval
        super().__init__(self._message())

    def _message(self) -> str:
        v = self.verdict
        why = "; ".join(v.reasons) or v.source
        if self.approval is not None:
            return (
                f"jev-firewall blocked '{v.tool_name}': held for approval and rejected by "
                f"{self.approval.resolver} ({why})"
            )
        return f"jev-firewall blocked '{v.tool_name}': {v.decision.value} ({why})"
