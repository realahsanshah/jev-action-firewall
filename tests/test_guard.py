from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from jev_firewall import ActionBlocked, AuditLog, ToolCall, read_audit
from jev_firewall.jev.fake import fixed_responder
from jev_firewall.verdict import Decision


def _events(audit: AuditLog) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for r in read_audit(audit.path):
        detail = r.get("decision") or r.get("approved") if r["event"] != "outcome" else r["status"]
        out.append((r["event"], detail))
    return out


def test_allow_executes(make_firewall: Any, audit: AuditLog) -> None:
    fw, _, approval = make_firewall(fixed_responder(severity="low_risk"))
    assert fw.guard(ToolCall("terminal", {"command": "ls"}, "list"), lambda: "ok") == "ok"
    assert approval.requests == []
    assert _events(audit) == [("verdict", "allow"), ("outcome", "executed")]


def test_deny_raises_and_never_executes(make_firewall: Any, audit: AuditLog) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    ran = []
    with pytest.raises(ActionBlocked) as info:
        fw.guard(ToolCall("terminal", {"command": "x"}, "g"), lambda: ran.append(1))
    assert ran == []
    assert info.value.verdict.decision is Decision.DENY
    assert info.value.approval is None
    assert _events(audit) == [("verdict", "deny"), ("outcome", "blocked")]


def test_hold_approved_executes(make_firewall: Any, audit: AuditLog) -> None:
    fw, _, approval = make_firewall(fixed_responder(severity="high_risk"), approved=True)
    assert fw.guard(ToolCall("terminal", {"command": "x"}, "g"), lambda: 42) == 42
    assert len(approval.requests) == 1
    assert approval.requests[0].tool_name == "terminal"
    assert _events(audit) == [("verdict", "hold"), ("approval", True), ("outcome", "executed")]


def test_hold_rejected_raises(make_firewall: Any, audit: AuditLog) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="high_risk"), approved=False)
    ran = []
    with pytest.raises(ActionBlocked) as info:
        fw.guard(ToolCall("terminal", {"command": "x"}, "g"), lambda: ran.append(1))
    assert ran == []
    assert info.value.approval is not None and info.value.approval.resolver == "test"
    assert "rejected by test" in str(info.value)
    assert _events(audit) == [("verdict", "hold"), ("approval", False), ("outcome", "blocked")]


def test_tool_error_is_audited_and_reraised(make_firewall: Any, audit: AuditLog) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="low_risk"))

    def boom() -> None:
        raise ValueError("disk full")

    with pytest.raises(ValueError, match="disk full"):
        fw.guard(ToolCall("terminal", {"command": "x"}, "g"), boom)
    assert _events(audit)[-1] == ("outcome", "error")


async def test_async_guard(make_firewall: Any, audit: AuditLog) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="high_risk"), approved=True)

    async def run() -> str:
        return "done"

    assert await fw.aguard(ToolCall("terminal", {"command": "x"}, "g"), run) == "done"

    fw2, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(ActionBlocked):
        await fw2.aguard(ToolCall("terminal", {"command": "x"}, "g"), run)


async def test_sync_check_inside_running_loop(make_firewall: Any) -> None:
    """Sync tools are sometimes invoked from a thread that already runs a loop."""
    fw, _, _ = make_firewall(fixed_responder(severity="high_risk"), approved=True)
    v = fw.check(ToolCall("terminal", {"command": "x"}, "g"))
    assert v.decision is Decision.HOLD


def test_core_does_not_import_frameworks() -> None:
    code = (
        "import sys, jev_firewall;"
        "bad=[m for m in ('langgraph','langchain_core','agents','google.adk','semantic_kernel') if m in sys.modules];"
        "print(bad); sys.exit(1 if bad else 0)"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def test_version_matches_package_metadata() -> None:
    from importlib.metadata import version

    import jev_firewall

    assert jev_firewall.__version__ == version("jev-firewall")
