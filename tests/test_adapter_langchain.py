from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("langchain_core")

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool

from jev_firewall import ActionBlocked, AuditLog, read_audit
from jev_firewall.adapters.langchain import JevFirewallCallbackHandler
from jev_firewall.jev.fake import fixed_responder

RAN: list[str] = []


@tool
def run_shell(command: str) -> str:
    """Run a shell command."""
    RAN.append(command)
    return f"ran {command}"


@tool
def failing(x: int) -> int:
    """Always fails."""
    raise ValueError("nope")


@pytest.fixture(autouse=True)
def _reset() -> None:
    RAN.clear()


def test_callback_allows_and_audits(make_firewall: Any, audit: AuditLog) -> None:
    fw, fake, _ = make_firewall(fixed_responder(severity="low_risk"))
    handler = JevFirewallCallbackHandler(fw, goal="List files")
    assert run_shell.invoke({"command": "ls"}, config={"callbacks": [handler]}) == "ran ls"
    state, _ = fake.requests[0]
    assert state == {
        "agent_goal": "List files",
        "proposed_action": {"tool_name": "run_shell", "tool_args": {"command": "ls"}},
    }
    assert [r["event"] for r in read_audit(audit.path)] == ["verdict", "outcome"]


def test_callback_deny_blocks_before_tool_runs(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(ActionBlocked):
        run_shell.invoke({"command": "shred db"}, config={"callbacks": [JevFirewallCallbackHandler(fw)]})
    assert RAN == []


async def test_callback_async_path(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(ActionBlocked):
        await run_shell.ainvoke(
            {"command": "shred db"}, config={"callbacks": [JevFirewallCallbackHandler(fw)]}
        )
    assert RAN == []


def test_goal_from_run_metadata(make_firewall: Any) -> None:
    fw, fake, _ = make_firewall(fixed_responder(severity="low_risk"))
    run_shell.invoke(
        {"command": "ls"},
        config={"callbacks": [JevFirewallCallbackHandler(fw)], "metadata": {"agent_goal": "Audit the repo"}},
    )
    assert fake.requests[0][0]["agent_goal"] == "Audit the repo"


def test_tool_error_is_audited(make_firewall: Any, audit: AuditLog) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="low_risk"))
    with pytest.raises(ValueError, match="nope"):
        failing.invoke({"x": 1}, config={"callbacks": [JevFirewallCallbackHandler(fw, goal="g")]})
    assert [r.get("status") for r in read_audit(audit.path) if r["event"] == "outcome"] == ["error"]


class _ToolCallingFake(GenericFakeChatModel):
    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self


def test_create_agent_middleware(make_firewall: Any) -> None:
    pytest.importorskip("langchain.agents")
    from langchain.agents import create_agent

    from jev_firewall.adapters.langchain import JevFirewallMiddleware

    fw, fake, _ = make_firewall(fixed_responder(severity="critical_danger"))
    model = _ToolCallingFake(
        messages=iter(
            [
                AIMessage(
                    "", tool_calls=[{"name": "run_shell", "args": {"command": "shred db"}, "id": "lc1"}]
                ),
                AIMessage("ok, I won't do that"),
            ]
        )
    )
    agent = create_agent(model, [run_shell], middleware=[JevFirewallMiddleware(fw)])
    out = agent.invoke({"messages": [{"role": "user", "content": "Clean up the database"}]})
    assert RAN == []
    blocked = [m for m in out["messages"] if isinstance(m, ToolMessage)]
    assert blocked[0].status == "error"
    assert "blocked by jev-firewall" in blocked[0].content
    assert fake.requests[0][0]["agent_goal"] == "Clean up the database"
