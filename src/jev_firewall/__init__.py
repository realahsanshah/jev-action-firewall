"""jev-firewall: a runtime action firewall for AI agents, powered by TypeSafe's Jev."""

from __future__ import annotations

from jev_firewall.approval import (
    ApprovalChannel,
    ApprovalRequest,
    ApprovalResult,
    CLIApproval,
    TimeoutDenyApproval,
    WebhookApproval,
)
from jev_firewall.audit import AuditLog, read_audit
from jev_firewall.engine import PolicyEngine
from jev_firewall.errors import ActionBlocked, FirewallError, JevUnavailable, PolicyConfigError
from jev_firewall.guard import Firewall
from jev_firewall.jev import FakeJevClient, JevClient, build_jev_client
from jev_firewall.policy import Policy, RiskThresholds
from jev_firewall.verdict import Decision, JevAssessment, SeverityTier, ToolCall, Verdict

__version__ = "0.1.0"

__all__ = [
    "ActionBlocked",
    "ApprovalChannel",
    "ApprovalRequest",
    "ApprovalResult",
    "AuditLog",
    "CLIApproval",
    "Decision",
    "FakeJevClient",
    "Firewall",
    "FirewallError",
    "JevAssessment",
    "JevClient",
    "JevUnavailable",
    "Policy",
    "PolicyConfigError",
    "PolicyEngine",
    "RiskThresholds",
    "SeverityTier",
    "TimeoutDenyApproval",
    "ToolCall",
    "Verdict",
    "WebhookApproval",
    "build_jev_client",
    "read_audit",
]
