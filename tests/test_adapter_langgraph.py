from __future__ import annotations

import uuid
from typing import Any

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.types import Command

from jev_firewall import ActionBlocked, AuditLog, Firewall, read_audit
from jev_firewall.adapters.langgraph import (
    LangGraphInterruptApproval,
    firewall_tool_node,
    first_human_message,
)
from jev_firewall.jev.fake import fixed_responder

EXECUTED: list[str] = []


@tool
def terminal(command: str) -> str:
    """Run a shell command."""
    EXECUTED.append(command)
    return f"ran: {command}"


def _input(command: str, goal: str = "tidy the build folder") -> dict[str, Any]:
    return {
        "messages": [
            HumanMessage(goal),
            AIMessage("", tool_calls=[{"name": "terminal", "args": {"command": command}, "id": "call_1"}]),
        ]
    }


def _run(node: Any) -> Any:
    """ToolNode needs a graph runtime, so wrap it in a one-node graph."""
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    return builder.compile()


@pytest.fixture(autouse=True)
def _reset() -> None:
    EXECUTED.clear()


def test_first_human_message() -> None:
    state = {"messages": [HumanMessage("do X"), AIMessage("ok"), HumanMessage("then Y")]}
    assert first_human_message(state) == "do X"
    assert first_human_message({"messages": [{"role": "user", "content": "dict form"}]}) == "dict form"
    assert first_human_message({"messages": []}) is None


def test_allow_runs_tool(make_firewall: Any, audit: AuditLog) -> None:
    fw, fake, _ = make_firewall(fixed_responder(severity="low_risk"))
    out = _run(firewall_tool_node([terminal], fw)).invoke(_input("ls dist"))
    assert EXECUTED == ["ls dist"]
    assert out["messages"][-1].content == "ran: ls dist"
    state, _ = fake.requests[0]
    assert state["agent_goal"] == "tidy the build folder"
    records = list(read_audit(audit.path))
    assert records[0]["call_id"] == "call_1"
    assert [r["event"] for r in records] == ["verdict", "outcome"]


def test_deny_raises_by_default(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(ActionBlocked):
        _run(firewall_tool_node([terminal], fw)).invoke(_input("shred -u prod.db"))
    assert EXECUTED == []


def test_deny_as_message(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    out = _run(firewall_tool_node([terminal], fw, on_block="message")).invoke(_input("shred -u prod.db"))
    msg = out["messages"][-1]
    assert isinstance(msg, ToolMessage) and msg.status == "error"
    assert "blocked by jev-firewall" in msg.content
    assert EXECUTED == []


def test_hold_uses_approval_channel(make_firewall: Any) -> None:
    fw, _, approval = make_firewall(fixed_responder(severity="high_risk"), approved=True)
    _run(firewall_tool_node([terminal], fw)).invoke(_input("rm -r dist"))
    assert EXECUTED == ["rm -r dist"]
    assert approval.requests[0].agent_goal == "tidy the build folder"


async def test_async_path(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="low_risk"))
    await _run(firewall_tool_node([terminal], fw)).ainvoke(_input("ls"))
    assert EXECUTED == ["ls"]
    fw2, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(ActionBlocked):
        await _run(firewall_tool_node([terminal], fw2)).ainvoke(_input("ls"))


def _graph(fw: Firewall) -> Any:
    def agent(state: MessagesState) -> dict[str, Any]:
        return {
            "messages": [
                AIMessage(
                    "", tool_calls=[{"name": "terminal", "args": {"command": "rm -r dist"}, "id": "c9"}]
                )
            ]
        }

    builder = StateGraph(MessagesState)
    builder.add_node("agent", agent)
    builder.add_node("tools", firewall_tool_node([terminal], fw))
    builder.add_edge(START, "agent")
    builder.add_edge("agent", "tools")
    return builder.compile(checkpointer=InMemorySaver())


@pytest.mark.parametrize(("resume", "ran"), [({"approved": True, "resolver": "alice"}, True), (False, False)])
def test_interrupt_hold_then_resume(make_engine: Any, audit: AuditLog, resume: Any, ran: bool) -> None:
    engine, fake = make_engine(fixed_responder(severity="high_risk"))
    fw = Firewall(engine, LangGraphInterruptApproval())
    graph = _graph(fw)
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}

    first = graph.invoke({"messages": [HumanMessage("clean up the build")]}, config)
    interrupts = first["__interrupt__"]
    assert interrupts[0].value["type"] == "jev_firewall_hold"
    assert interrupts[0].value["tool_name"] == "terminal"
    assert EXECUTED == []

    if ran:
        graph.invoke(Command(resume=resume), config)
        assert EXECUTED == ["rm -r dist"]
    else:
        with pytest.raises(ActionBlocked):
            graph.invoke(Command(resume=resume), config)
        assert EXECUTED == []

    # The verdict is reused on resume: one Jev call, one verdict record.
    assert len(fake.requests) == 1
    events = [r["event"] for r in read_audit(audit.path)]
    assert events.count("verdict") == 1
    assert "approval" in events
