"""Google ADK adapter: `before_tool_callback` for one agent, or a plugin for a whole Runner.

Per agent:

    fw_cb = JevFirewallCallbacks(firewall)
    agent = LlmAgent(..., before_tool_callback=fw_cb.before_tool_callback,
                     after_tool_callback=fw_cb.after_tool_callback)

Every agent in an app:

    app = App(name="ops", root_agent=root_agent, plugins=[JevFirewallPlugin(firewall)])
    runner = InMemoryRunner(app=app)

On a block, `on_block="result"` skips the tool and returns `{"error": ..., "jev_firewall":
{...}}` to the model as the tool result (ADK's idiomatic veto). `on_block="raise"` raises
`ActionBlocked`: from agent-level callbacks it propagates as is; ADK's plugin manager wraps
plugin exceptions in `RuntimeError`, so from the plugin it arrives as that error's
`__cause__`. Defaults: callbacks raise, the plugin returns a result.

Requires `pip install jev-firewall[google_adk]`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

try:
    from google.adk.plugins.base_plugin import BasePlugin
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "jev_firewall.adapters.google_adk needs its framework: pip install 'jev-firewall[google_adk]'"
    ) from exc

from jev_firewall.adapters._common import content_text
from jev_firewall.errors import ActionBlocked
from jev_firewall.guard import Firewall
from jev_firewall.verdict import ToolCall

FRAMEWORK = "google_adk"

AdkGoal = str | Callable[[ToolContext], str | None] | None


def user_content_goal(tool_context: ToolContext) -> str | None:
    """Default `agent_goal`: the user message that started this invocation."""
    content = tool_context.user_content
    if content is None or not content.parts:
        return None
    return content_text([p.text for p in content.parts if p.text])


class JevFirewallCallbacks:
    def __init__(
        self,
        firewall: Firewall,
        *,
        goal: AdkGoal = user_content_goal,
        on_block: Literal["raise", "result"] = "raise",
    ) -> None:
        self.firewall = firewall
        self.goal = goal
        self.on_block = on_block

    def _call(self, tool: BaseTool, args: dict[str, Any], ctx: ToolContext) -> ToolCall:
        extra: dict[str, Any] = {}
        if ctx.function_call_id:
            extra["call_id"] = ctx.function_call_id
        goal = self.goal(ctx) if callable(self.goal) else self.goal
        return ToolCall(tool.name, dict(args), goal, framework=FRAMEWORK, **extra)

    async def before_tool_callback(
        self, tool: BaseTool, args: dict[str, Any], tool_context: ToolContext
    ) -> dict[str, Any] | None:
        try:
            await self.firewall.acheck(self._call(tool, args, tool_context))
        except ActionBlocked as exc:
            if self.on_block == "raise":
                raise
            return {
                "error": f"Action blocked by jev-firewall: {exc}",
                "jev_firewall": {
                    "decision": exc.verdict.decision.value,
                    "reasons": list(exc.verdict.reasons),
                },
            }
        return None  # only None lets ADK run the tool

    async def after_tool_callback(
        self, tool: BaseTool, args: dict[str, Any], tool_context: ToolContext, tool_response: Any
    ) -> dict[str, Any] | None:
        if tool_context.function_call_id:
            self.firewall.record_outcome(tool_context.function_call_id, "executed")
        return None


class JevFirewallPlugin(BasePlugin):
    """Runner-wide plugin. Plugin callbacks run before agent-level tool callbacks."""

    def __init__(
        self,
        firewall: Firewall,
        *,
        goal: AdkGoal = user_content_goal,
        on_block: Literal["raise", "result"] = "result",
        name: str = "jev_firewall",
    ) -> None:
        super().__init__(name=name)
        self._cb = JevFirewallCallbacks(firewall, goal=goal, on_block=on_block)

    async def before_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext
    ) -> dict[str, Any] | None:
        return await self._cb.before_tool_callback(tool, tool_args, tool_context)

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        return await self._cb.after_tool_callback(tool, tool_args, tool_context, result)
