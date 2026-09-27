from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("agents")

from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.testing import ScriptedModel, assistant_message, function_call

from jev_firewall import ActionBlocked, AuditLog, read_audit
from jev_firewall.adapters.openai_agents import protect_tools
from jev_firewall.jev.fake import fixed_responder

set_tracing_disabled(True)

RAN: list[str] = []


def make_tool() -> Any:
    @function_tool
    def run_shell(command: str) -> str:
        """Run a shell command."""
        RAN.append(command)
        return f"ran {command}"

    return run_shell


@pytest.fixture(autouse=True)
def _reset() -> None:
    RAN.clear()


def _agent(fw: Any, command: str, **kw: Any) -> Agent[Any]:
    model = ScriptedModel(
        [
            [function_call("run_shell", {"command": command}, call_id="call_42")],
            [assistant_message("done")],
        ]
    )
    return Agent(name="ops", model=model, tools=protect_tools([make_tool()], fw, **kw))


async def test_allow_runs_and_is_audited(make_firewall: Any, audit: AuditLog) -> None:
    fw, fake, _ = make_firewall(fixed_responder(severity="low_risk"))
    result = await Runner.run(_agent(fw, "ls -la"), "List the files in the repo")
    assert result.final_output == "done"
    assert RAN == ["ls -la"]
    state, _ = fake.requests[0]
    assert state["agent_goal"] == "List the files in the repo"
    assert state["proposed_action"] == {"tool_name": "run_shell", "tool_args": {"command": "ls -la"}}
    events = [(r["event"], r["call_id"]) for r in read_audit(audit.path)]
    assert events == [("verdict", "call_42"), ("outcome", "call_42")]


async def test_deny_raises_action_blocked(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(ActionBlocked):
        await Runner.run(_agent(fw, "rm -rf /"), "Clean up")
    assert RAN == []


async def test_deny_reject_lets_model_continue(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    result = await Runner.run(_agent(fw, "shred prod.db", on_block="reject"), "Clean up")
    assert RAN == []
    assert result.final_output == "done"
    outputs = [str(getattr(i, "output", "")) for i in result.new_items]
    assert any("blocked by jev-firewall" in o for o in outputs)


async def test_hold_goes_to_approval(make_firewall: Any) -> None:
    fw, _, approval = make_firewall(fixed_responder(severity="high_risk"), approved=True)
    await Runner.run(_agent(fw, "rm -r build"), "Clean the build")
    assert RAN == ["rm -r build"]
    assert approval.requests[0].tool_name == "run_shell"
