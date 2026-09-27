from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import pytest

pytest.importorskip("google.adk")

from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from jev_firewall import ActionBlocked, AuditLog, read_audit
from jev_firewall.adapters.google_adk import JevFirewallCallbacks, JevFirewallPlugin
from jev_firewall.jev.fake import fixed_responder

RAN: list[str] = []


def run_shell(command: str) -> dict[str, str]:
    """Run a shell command."""
    RAN.append(command)
    return {"output": f"ran {command}"}


class ScriptedLlm(BaseLlm):
    """Calls `run_shell` once, then answers with text after seeing the tool result."""

    model: str = "scripted"
    command: str = "ls"

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        seen_result = any(p.function_response for c in llm_request.contents for p in (c.parts or []))
        if seen_result:
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text="done")]))
        else:
            call = types.FunctionCall(name="run_shell", args={"command": self.command}, id="adk_call_1")
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=call)]))


@pytest.fixture(autouse=True)
def _reset() -> None:
    RAN.clear()


async def _run(agent: LlmAgent, text: str, plugins: list[Any] | None = None) -> list[Any]:
    runner = InMemoryRunner(app=App(name="t", root_agent=agent, plugins=plugins or []))
    session = await runner.session_service.create_session(app_name="t", user_id="u")
    msg = types.Content(role="user", parts=[types.Part(text=text)])
    return [e async for e in runner.run_async(user_id="u", session_id=session.id, new_message=msg)]


def _agent(command: str, cb: JevFirewallCallbacks | None = None) -> LlmAgent:
    kwargs: dict[str, Any] = {}
    if cb is not None:
        kwargs = {
            "before_tool_callback": cb.before_tool_callback,
            "after_tool_callback": cb.after_tool_callback,
        }
    return LlmAgent(name="ops", model=ScriptedLlm(command=command), tools=[run_shell], **kwargs)


async def test_allow_runs_and_uses_user_goal(make_firewall: Any, audit: AuditLog) -> None:
    fw, fake, _ = make_firewall(fixed_responder(severity="low_risk"))
    await _run(_agent("ls -la", JevFirewallCallbacks(fw)), "List the repo files")
    assert RAN == ["ls -la"]
    state, _ = fake.requests[0]
    assert state["agent_goal"] == "List the repo files"
    events = [(r["event"], r["call_id"]) for r in read_audit(audit.path)]
    assert events == [("verdict", "adk_call_1"), ("outcome", "adk_call_1")]


async def test_deny_raises(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(ActionBlocked):
        await _run(_agent("shred prod.db", JevFirewallCallbacks(fw)), "Clean up")
    assert RAN == []


async def test_deny_as_tool_result(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    events = await _run(_agent("shred prod.db", JevFirewallCallbacks(fw, on_block="result")), "Clean up")
    assert RAN == []
    responses = [
        p.function_response.response
        for e in events
        for p in (e.content.parts if e.content else [])
        if p.function_response
    ]
    assert "blocked by jev-firewall" in responses[0]["error"]


async def test_plugin_covers_agent_without_callbacks(make_firewall: Any) -> None:
    fw, _, approval = make_firewall(fixed_responder(severity="high_risk"), approved=False)
    events = await _run(_agent("rm -r data"), "Tidy up", plugins=[JevFirewallPlugin(fw)])
    assert RAN == []
    assert approval.requests[0].tool_name == "run_shell"
    assert any(p.function_response for e in events for p in (e.content.parts if e.content else []))


async def test_plugin_raise_mode_chains_action_blocked(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(RuntimeError) as info:
        await _run(_agent("shred prod.db"), "Tidy up", plugins=[JevFirewallPlugin(fw, on_block="raise")])
    assert isinstance(info.value.__cause__, ActionBlocked)
    assert RAN == []
