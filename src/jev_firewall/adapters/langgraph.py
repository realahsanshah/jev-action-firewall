"""LangGraph adapter: intercept tool calls in `ToolNode` via `wrap_tool_call`.

    from jev_firewall import Firewall
    from jev_firewall.adapters.langgraph import firewall_tool_node

    firewall = Firewall.from_yaml("policy.yaml")
    tools_node = firewall_tool_node([terminal, send_email], firewall)
    builder.add_node("tools", tools_node)

HOLD is resolved by the firewall's approval channel. To pause the graph instead (needs a
checkpointer), pass `LangGraphInterruptApproval()` as the Firewall's approval channel and
resume with `Command(resume={"approved": True, "resolver": "alice"})`.

Requires `pip install jev-firewall[langgraph]`.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Literal

from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.prebuilt import ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command, interrupt

from jev_firewall.adapters._common import first_user_text
from jev_firewall.approval import ApprovalRequest, ApprovalResult
from jev_firewall.errors import ActionBlocked
from jev_firewall.guard import Firewall
from jev_firewall.verdict import Decision, ToolCall, Verdict

GoalSource = str | Callable[[Any], str | None] | None
ToolResult = ToolMessage | Command[Any]

FRAMEWORK = "langgraph"


def first_human_message(state: Any) -> str | None:
    """Default `agent_goal`: the first human message in `state["messages"]`."""
    messages = state.get("messages") if isinstance(state, Mapping) else getattr(state, "messages", None)
    return first_user_text(messages)


class JevToolCallWrapper:
    """A `wrap_tool_call` / `awrap_tool_call` pair for `ToolNode` (or any compatible hook).

    `on_block="raise"` lets `ActionBlocked` propagate and stops the run.
    `on_block="message"` returns an error `ToolMessage` instead so the model can recover.
    """

    def __init__(
        self,
        firewall: Firewall,
        *,
        goal: GoalSource = first_human_message,
        on_block: Literal["raise", "message"] = "raise",
        cache_size: int = 1024,
    ) -> None:
        self.firewall = firewall
        self.goal = goal
        self.on_block = on_block
        # Verdicts for held calls, keyed by tool_call id. A LangGraph interrupt re-runs the node
        # on resume; reusing the verdict avoids a second Jev call and a second audit record.
        self._held: OrderedDict[str, Verdict] = OrderedDict()
        self._cache_size = cache_size

    def _call(self, request: ToolCallRequest) -> ToolCall:
        tc = request.tool_call
        goal = self.goal(request.state) if callable(self.goal) else self.goal
        kwargs: dict[str, Any] = {}
        if tc.get("id"):
            kwargs["call_id"] = str(tc["id"])
        return ToolCall(tc["name"], dict(tc.get("args") or {}), goal, framework=FRAMEWORK, **kwargs)

    def _remember(self, v: Verdict) -> None:
        if v.decision is Decision.HOLD:
            self._held[v.call_id] = v
            while len(self._held) > self._cache_size:
                self._held.popitem(last=False)

    def _blocked(self, request: ToolCallRequest, exc: ActionBlocked) -> ToolMessage:
        if self.on_block == "raise":
            raise exc
        return ToolMessage(
            content=f"Action blocked by jev-firewall: {exc}",
            name=request.tool_call["name"],
            tool_call_id=request.tool_call["id"] or "",
            status="error",
        )

    def __call__(
        self, request: ToolCallRequest, execute: Callable[[ToolCallRequest], ToolResult]
    ) -> ToolResult:
        call = self._call(request)
        verdict = self._held.get(call.call_id) or self.firewall.engine.evaluate(call)
        self._remember(verdict)
        try:
            self.firewall.resolve(verdict)
        except ActionBlocked as exc:
            self._held.pop(call.call_id, None)
            return self._blocked(request, exc)
        self._held.pop(call.call_id, None)
        return self.firewall.guard_executed(call, lambda: execute(request))

    async def acall(
        self, request: ToolCallRequest, execute: Callable[[ToolCallRequest], Awaitable[ToolResult]]
    ) -> ToolResult:
        call = self._call(request)
        verdict = self._held.get(call.call_id) or await self.firewall.engine.aevaluate(call)
        self._remember(verdict)
        try:
            await self.firewall.aresolve(verdict)
        except ActionBlocked as exc:
            self._held.pop(call.call_id, None)
            return self._blocked(request, exc)
        self._held.pop(call.call_id, None)
        return await self.firewall.aguard_executed(call, lambda: execute(request))


def firewall_tool_node(
    tools: Sequence[BaseTool | Callable[..., Any]],
    firewall: Firewall,
    *,
    goal: GoalSource = first_human_message,
    on_block: Literal["raise", "message"] = "raise",
    **tool_node_kwargs: Any,
) -> ToolNode:
    """A `ToolNode` whose every tool call goes through the firewall first."""
    wrapper = JevToolCallWrapper(firewall, goal=goal, on_block=on_block)
    return ToolNode(tools, wrap_tool_call=wrapper, awrap_tool_call=wrapper.acall, **tool_node_kwargs)


class LangGraphInterruptApproval:
    """Approval channel that pauses the graph with `interrupt()` (requires a checkpointer).

    The interrupt value is `{"type": "jev_firewall_hold", ...ApprovalRequest}`. Resume with
    `Command(resume=True)`, `Command(resume="yes")` or
    `Command(resume={"approved": True, "resolver": "alice", "note": "..."})`.
    """

    async def request(self, req: ApprovalRequest) -> ApprovalResult:
        answer = interrupt({"type": "jev_firewall_hold", **req.to_dict()})
        if isinstance(answer, Mapping):
            return ApprovalResult(
                approved=answer.get("approved") is True,
                resolver=str(answer.get("resolver") or "langgraph:resume"),
                note=None if answer.get("note") is None else str(answer["note"]),
            )
        if isinstance(answer, str):
            return ApprovalResult(
                answer.strip().lower() in {"y", "yes", "approve", "approved"}, "langgraph:resume"
            )
        return ApprovalResult(answer is True, "langgraph:resume")
