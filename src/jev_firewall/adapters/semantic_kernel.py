"""Semantic Kernel adapter: a FUNCTION_INVOCATION filter in front of every kernel function.

    from semantic_kernel.filters import FilterTypes
    from jev_firewall.adapters.semantic_kernel import JevFunctionInvocationFilter

    kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, JevFunctionInvocationFilter(firewall, goal=task))

Function invocation filters also run for functions the model calls through automatic
function calling, so one filter covers both paths.

Only the function's declared parameters are sent as `tool_args`; anything else riding in
`KernelArguments` (chat history, execution settings) never reaches Jev.

On a block, `on_block="raise"` (default) raises `ActionBlocked`. `Kernel.invoke` wraps every
function error in `KernelInvokeException`, so from there it arrives as that exception's
`__cause__`. `on_block="result"` skips the function and sets its result to a refusal
message the model can read, which is what you want under automatic function calling.

Requires `pip install jev-firewall[semantic_kernel]`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal

try:
    from semantic_kernel.filters.functions.function_invocation_context import FunctionInvocationContext
    from semantic_kernel.functions.function_result import FunctionResult
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "jev_firewall.adapters.semantic_kernel needs its framework: pip install 'jev-firewall[semantic_kernel]'"
    ) from exc

from jev_firewall.adapters._common import first_user_text
from jev_firewall.errors import ActionBlocked
from jev_firewall.guard import Firewall
from jev_firewall.verdict import ToolCall

FRAMEWORK = "semantic_kernel"

SkGoal = str | Callable[[FunctionInvocationContext], str | None] | None
Next = Callable[[FunctionInvocationContext], Awaitable[None]]


def goal_from_chat_history(context: FunctionInvocationContext) -> str | None:
    """Goal from a `chat_history` argument, if the caller passed one."""
    history = context.arguments.get("chat_history") if context.arguments is not None else None
    return first_user_text(getattr(history, "messages", None))


class JevFunctionInvocationFilter:
    def __init__(
        self,
        firewall: Firewall,
        *,
        goal: SkGoal = goal_from_chat_history,
        on_block: Literal["raise", "result"] = "raise",
    ) -> None:
        self.firewall = firewall
        self.goal = goal
        self.on_block = on_block

    def _call(self, context: FunctionInvocationContext) -> ToolCall:
        fn = context.function
        declared = {p.name for p in fn.metadata.parameters if p.name}
        raw = dict(context.arguments or {})
        args = {k: v for k, v in raw.items() if k in declared}
        goal = self.goal(context) if callable(self.goal) else self.goal
        return ToolCall(fn.fully_qualified_name, args, goal, framework=FRAMEWORK)

    async def __call__(self, context: FunctionInvocationContext, next: Next) -> None:
        call = self._call(context)
        try:
            await self.firewall.acheck(call)
        except ActionBlocked as exc:
            if self.on_block == "raise":
                raise
            context.result = FunctionResult(
                function=context.function.metadata, value=f"Action blocked by jev-firewall: {exc}"
            )
            return
        await self.firewall.aguard_executed(call, lambda: next(context))
