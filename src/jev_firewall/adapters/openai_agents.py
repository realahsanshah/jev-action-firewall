"""OpenAI Agents SDK adapter: a tool input guardrail that runs before every function tool.

    from agents import Agent
    from jev_firewall.adapters.openai_agents import protect_tools

    agent = Agent(name="ops", tools=protect_tools([run_shell, send_email], firewall))

`protect_tools` prepends the firewall to each `FunctionTool.tool_input_guardrails` (and adds
an output guardrail that records the outcome in the audit log). You can also attach
`jev_tool_input_guardrail(firewall)` yourself via `@function_tool(tool_input_guardrails=[...])`.

On a block, `on_block="raise"` (default) propagates `ActionBlocked` out of `Runner.run`;
`on_block="reject"` sends the model a rejection message instead of the tool result and lets
the run continue.

Requires `pip install jev-firewall[openai_sdk]`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any, Literal, TypeVar

from agents import FunctionTool, ToolGuardrailFunctionOutput
from agents.exceptions import AgentsException
from agents.tool_context import ToolContext
from agents.tool_guardrails import (
    ToolInputGuardrail,
    ToolInputGuardrailData,
    ToolOutputGuardrail,
    ToolOutputGuardrailData,
)

from jev_firewall.adapters._common import first_user_text
from jev_firewall.errors import ActionBlocked
from jev_firewall.guard import Firewall
from jev_firewall.verdict import ToolCall

FRAMEWORK = "openai_agents"

AgentsGoal = str | Callable[[ToolContext[Any]], str | None] | None
T = TypeVar("T")


class AgentsActionBlocked(ActionBlocked, AgentsException):
    """`ActionBlocked` that the Agents SDK re-raises unchanged.

    The SDK wraps any tool-time exception that is not an `AgentsException` in `UserError`;
    inheriting from both keeps `except ActionBlocked` working for callers.
    """


def first_user_input(ctx: ToolContext[Any]) -> str | None:
    """Default `agent_goal`: the first user message of the current turn's input."""
    return first_user_text(getattr(ctx, "turn_input", None))


def _args(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {"input": raw}
    return parsed if isinstance(parsed, dict) else {"input": parsed}


def jev_tool_input_guardrail(
    firewall: Firewall,
    *,
    goal: AgentsGoal = first_user_input,
    on_block: Literal["raise", "reject"] = "raise",
) -> ToolInputGuardrail[Any]:
    async def jev_firewall(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        ctx = data.context
        agent_goal = goal(ctx) if callable(goal) else goal
        call = ToolCall(
            ctx.tool_name,
            _args(ctx.tool_arguments),
            agent_goal,
            call_id=ctx.tool_call_id,
            framework=FRAMEWORK,
        )
        try:
            verdict = await firewall.acheck(call)
        except ActionBlocked as exc:
            if on_block == "raise":
                raise AgentsActionBlocked(exc.verdict, exc.approval) from exc
            return ToolGuardrailFunctionOutput.reject_content(
                f"Action blocked by jev-firewall: {exc}", output_info=exc.verdict.to_dict()
            )
        return ToolGuardrailFunctionOutput.allow(output_info={"decision": verdict.decision.value})

    return ToolInputGuardrail(guardrail_function=jev_firewall, name="jev_firewall")


def jev_tool_output_recorder(firewall: Firewall) -> ToolOutputGuardrail[Any]:
    """Output guardrail that only records `executed` in the audit log; it never blocks."""

    def jev_firewall_outcome(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
        firewall.record_outcome(data.context.tool_call_id, "executed")
        return ToolGuardrailFunctionOutput.allow()

    return ToolOutputGuardrail(guardrail_function=jev_firewall_outcome, name="jev_firewall_outcome")


def protect_tools(
    tools: Sequence[T],
    firewall: Firewall,
    *,
    goal: AgentsGoal = first_user_input,
    on_block: Literal["raise", "reject"] = "raise",
) -> list[T]:
    """Attach the firewall to every `FunctionTool` in `tools` (in place) and return them.

    Hosted tools (web search, code interpreter, ...) run on OpenAI's side and have no input
    guardrail hook; they are returned unchanged.
    """
    guard = jev_tool_input_guardrail(firewall, goal=goal, on_block=on_block)
    recorder = jev_tool_output_recorder(firewall)
    for t in tools:
        if isinstance(t, FunctionTool):
            t.tool_input_guardrails = [guard, *(t.tool_input_guardrails or [])]
            t.tool_output_guardrails = [*(t.tool_output_guardrails or []), recorder]
    return list(tools)
