from __future__ import annotations

import asyncio
import io
import json
import time
from typing import Any

import httpx2
import pytest

from jev_firewall import CLIApproval, TimeoutDenyApproval, ToolCall, WebhookApproval
from jev_firewall.approval import ApprovalRequest, build_approval
from jev_firewall.jev.fake import fixed_responder
from jev_firewall.policy import ApprovalConfig


@pytest.fixture
def held_request(make_engine: Any) -> ApprovalRequest:
    engine, _ = make_engine(fixed_responder(severity="high_risk"))
    v = engine.evaluate(ToolCall("send_email", {"to": "x@y.com", "password": "p"}, "email x"))
    return ApprovalRequest.from_verdict(v)


@pytest.mark.parametrize(("answer", "approved"), [("y", True), ("YES", True), ("n", False), ("", False)])
async def test_cli_approval(held_request: ApprovalRequest, answer: str, approved: bool) -> None:
    out = io.StringIO()
    result = await CLIApproval(input_fn=lambda _: answer, out=out).request(held_request)
    assert result.approved is approved
    assert result.resolver.startswith("cli:")
    shown = out.getvalue()
    assert "send_email" in shown and "severity=high_risk" in shown
    assert '"password": "[REDACTED:secret]"' in shown


async def test_cli_timeout_rejects(held_request: ApprovalRequest) -> None:
    def slow(_: str) -> str:
        time.sleep(0.5)
        return "y"

    result = await CLIApproval(timeout_s=0.05, input_fn=slow, out=io.StringIO()).request(held_request)
    assert not result.approved and result.resolver == "cli:timeout"


async def test_cli_eof_rejects(held_request: ApprovalRequest) -> None:
    def eof(_: str) -> str:
        raise EOFError

    result = await CLIApproval(input_fn=eof, out=io.StringIO()).request(held_request)
    assert not result.approved and result.resolver == "cli:eof"


async def test_webhook_immediate_decision(held_request: ApprovalRequest) -> None:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(json.loads(request.content))
        return httpx2.Response(200, json={"approved": True, "resolver": "slack:alice"})

    wh = WebhookApproval("https://approvals.test/hook", timeout_s=2, transport=httpx2.MockTransport(handler))
    result = await wh.request(held_request)
    assert result.approved and result.resolver == "slack:alice"
    assert seen[0]["tool_name"] == "send_email"
    assert seen[0]["tool_args"]["password"] == "[REDACTED:secret]"


async def test_webhook_polls_until_decided(held_request: ApprovalRequest) -> None:
    polls = {"n": 0}

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST":
            return httpx2.Response(202, json={"status": "pending", "poll_url": "https://approvals.test/p/1"})
        polls["n"] += 1
        if polls["n"] < 3:
            return httpx2.Response(200, json={"status": "pending", "poll_url": "https://approvals.test/p/1"})
        return httpx2.Response(200, json={"approved": False, "resolver": "bob", "note": "not today"})

    wh = WebhookApproval(
        "https://approvals.test/hook",
        timeout_s=2,
        poll_interval_s=0.01,
        transport=httpx2.MockTransport(handler),
    )
    result = await wh.request(held_request)
    assert not result.approved and result.resolver == "bob" and result.note == "not today"
    assert polls["n"] == 3


async def test_webhook_timeout_and_errors_reject(held_request: ApprovalRequest) -> None:
    pending = httpx2.MockTransport(
        lambda r: httpx2.Response(200, json={"status": "pending", "poll_url": "https://a.test/p"})
    )
    wh = WebhookApproval("https://a.test/h", timeout_s=0.1, poll_interval_s=0.02, transport=pending)
    assert (await wh.request(held_request)).resolver == "webhook:timeout"

    broken = httpx2.MockTransport(lambda r: httpx2.Response(500, text="nope"))
    wh = WebhookApproval("https://a.test/h", timeout_s=1, transport=broken)
    result = await wh.request(held_request)
    assert not result.approved and result.resolver == "webhook:error"


async def test_timeout_deny(held_request: ApprovalRequest) -> None:
    assert (await TimeoutDenyApproval().request(held_request)).resolver == "auto:deny"

    class Slow:
        async def request(self, req: ApprovalRequest) -> Any:
            await asyncio.sleep(1)

    result = await TimeoutDenyApproval(Slow(), timeout_s=0.05).request(held_request)
    assert not result.approved and result.resolver == "auto:timeout"


def test_build_approval() -> None:
    assert isinstance(build_approval(None), TimeoutDenyApproval)
    assert isinstance(build_approval(ApprovalConfig(channel="cli", timeout_s=5)), CLIApproval)
    wh = build_approval(ApprovalConfig(channel="webhook", timeout_s=5, webhook_url="https://x.test"))
    assert isinstance(wh, WebhookApproval)
