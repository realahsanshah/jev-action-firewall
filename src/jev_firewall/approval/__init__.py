"""Approval channels for actions the firewall holds."""

from __future__ import annotations

from jev_firewall.approval.base import ApprovalChannel, ApprovalRequest, ApprovalResult
from jev_firewall.approval.cli import CLIApproval
from jev_firewall.approval.timeout_deny import TimeoutDenyApproval
from jev_firewall.approval.webhook import WebhookApproval
from jev_firewall.errors import PolicyConfigError
from jev_firewall.policy import ApprovalConfig

__all__ = [
    "ApprovalChannel",
    "ApprovalRequest",
    "ApprovalResult",
    "CLIApproval",
    "TimeoutDenyApproval",
    "WebhookApproval",
    "build_approval",
]


def build_approval(config: ApprovalConfig | None) -> ApprovalChannel:
    """Channel described by `policy.yaml`. No `approval:` section means held actions are denied."""
    if config is None or config.channel == "timeout_deny":
        return TimeoutDenyApproval()
    if config.channel == "cli":
        return CLIApproval(timeout_s=config.timeout_s)
    if config.channel == "webhook":
        if not config.webhook_url or config.timeout_s is None:
            raise PolicyConfigError("webhook approval needs approval.webhook_url and approval.timeout_s")
        return WebhookApproval(config.webhook_url, timeout_s=config.timeout_s)
    raise PolicyConfigError(f"unknown approval channel {config.channel!r}")
