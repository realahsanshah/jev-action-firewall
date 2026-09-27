"""LangChain adapter.

Two hooks, same core:

`JevFirewallCallbackHandler` works with any LangChain tool invocation (LCEL chains, legacy
agents, `tool.invoke`). It runs in `on_tool_start` and raises `ActionBlocked` before the
tool body executes:

    handler = JevFirewallCallbackHandler(firewall, goal="Summarize the Q3 report")
    tool.invoke(args, config={"callbacks": [handler]})
    # or pass the goal per run: config={"callbacks": [handler], "metadata": {"agent_goal": "..."}}

`JevFirewallMiddleware` plugs into `langchain.agents.create_agent` (LangChain 1.x):

    agent = create_agent(model, tools, middleware=[JevFirewallMiddleware(firewall)])

Requires `pip install jev-firewall[langchain]`.
"""

from __future__ import annotations

import threading
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Literal
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from jev_firewall.guard import Firewall
from jev_firewall.verdict import ToolCall

FRAMEWORK = "langchain"

CallbackGoal = str | Callable[[Mapping[str, Any]], str | None] | None


class JevFirewallCallbackHandler(BaseCallbackHandler):
    """Vetoes tool calls from `on_tool_start`.

    This is a *sync* handler on purpose: LangChain swallows exceptions from async handlers on
    the sync tool path, so an async handler could not block anything there. Sync handlers run
    on both paths and `raise_error = True` makes their exceptions abort the tool.
    """

    raise_error: bool = True

    def __init__(self, firewall: Firewall, *, goal: CallbackGoal = None) -> None:
        super().__init__()
        self.firewall = firewall
        self.goal = goal
        self._runs: dict[UUID, str] = {}
        self._lock = threading.Lock()

    def _goal(self, metadata: Mapping[str, Any]) -> str | None:
        if callable(self.goal):
            return self.goal(metadata)
        if self.goal is not None:
            return self.goal
        g = metadata.get("agent_goal")
        return None if g is None else str(g)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        name = str(serialized.get("name") or kwargs.get("name") or "unknown_tool")
        args: dict[str, Any] = dict(inputs) if inputs is not None else {"input": input_str}
        extra: dict[str, Any] = {}
        if kwargs.get("tool_call_id"):
            extra["call_id"] = str(kwargs["tool_call_id"])
        call = ToolCall(name, args, self._goal(metadata or {}), framework=FRAMEWORK, **extra)
        self.firewall.check(call)  # raises ActionBlocked on DENY or a rejected HOLD
        with self._lock:
            self._runs[run_id] = call.call_id

    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            call_id = self._runs.pop(run_id, None)
        if call_id is not None:
            self.firewall.record_outcome(call_id, "executed")

    def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            call_id = self._runs.pop(run_id, None)
        if call_id is not None:
            self.firewall.record_outcome(call_id, "error", f"{type(error).__name__}: {error}")


try:
    from langchain.agents.middleware import AgentMiddleware
    from langchain.tools.tool_node import ToolCallRequest
    from langchain_core.messages import ToolMessage
    from langgraph.types import Command
except ImportError:  # pragma: no cover - only `langchain-core` installed
    pass
else:
    from jev_firewall.adapters.langgraph import GoalSource, JevToolCallWrapper, first_human_message

    class JevFirewallMiddleware(AgentMiddleware):
        """`create_agent` middleware; the same interception as the LangGraph adapter."""

        def __init__(
            self,
            firewall: Firewall,
            *,
            goal: GoalSource = first_human_message,
            on_block: Literal["raise", "message"] = "message",
        ) -> None:
            super().__init__()
            self._wrapper = JevToolCallWrapper(firewall, goal=goal, on_block=on_block)

        def wrap_tool_call(
            self,
            request: ToolCallRequest,
            handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
        ) -> ToolMessage | Command[Any]:
            return self._wrapper(request, handler)

        async def awrap_tool_call(
            self,
            request: ToolCallRequest,
            handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
        ) -> ToolMessage | Command[Any]:
            return await self._wrapper.acall(request, handler)
