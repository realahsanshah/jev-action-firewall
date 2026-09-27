from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("semantic_kernel")

from semantic_kernel import Kernel
from semantic_kernel.contents import ChatHistory
from semantic_kernel.exceptions import KernelInvokeException
from semantic_kernel.filters import FilterTypes
from semantic_kernel.functions import KernelArguments, kernel_function

from jev_firewall import ActionBlocked, AuditLog, read_audit
from jev_firewall.adapters.semantic_kernel import JevFunctionInvocationFilter
from jev_firewall.jev.fake import fixed_responder

RAN: list[str] = []


class ShellPlugin:
    @kernel_function(name="run", description="Run a shell command.")
    def run(self, command: str) -> str:
        RAN.append(command)
        return f"ran {command}"


@pytest.fixture(autouse=True)
def _reset() -> None:
    RAN.clear()


def _kernel(fw: Any, **kw: Any) -> Kernel:
    kernel = Kernel()
    kernel.add_plugin(ShellPlugin(), plugin_name="shell")
    kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, JevFunctionInvocationFilter(fw, **kw))
    return kernel


async def test_allow_runs_and_only_declared_args_are_sent(make_firewall: Any, audit: AuditLog) -> None:
    fw, fake, _ = make_firewall(fixed_responder(severity="low_risk"))
    history = ChatHistory()
    history.add_user_message("List the repo files")
    history.add_assistant_message("sure, secret internal reasoning here")
    result = await _kernel(fw).invoke(
        plugin_name="shell",
        function_name="run",
        arguments=KernelArguments(command="ls", chat_history=history),
    )
    assert str(result) == "ran ls"
    state, _ = fake.requests[0]
    assert state["proposed_action"] == {"tool_name": "shell-run", "tool_args": {"command": "ls"}}
    assert state["agent_goal"] == "List the repo files"
    assert "secret internal reasoning" not in str(state)
    assert [r["event"] for r in read_audit(audit.path)] == ["verdict", "outcome"]


async def test_deny_raises(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    with pytest.raises(KernelInvokeException) as info:
        await _kernel(fw, goal="clean up").invoke(
            plugin_name="shell", function_name="run", arguments=KernelArguments(command="shred db")
        )
    assert isinstance(info.value.__cause__, ActionBlocked)
    assert RAN == []


async def test_deny_as_result(make_firewall: Any) -> None:
    fw, _, _ = make_firewall(fixed_responder(severity="critical_danger"))
    result = await _kernel(fw, goal="clean up", on_block="result").invoke(
        plugin_name="shell", function_name="run", arguments=KernelArguments(command="shred db")
    )
    assert RAN == []
    assert "blocked by jev-firewall" in str(result)


async def test_hold_approved(make_firewall: Any) -> None:
    fw, _, approval = make_firewall(fixed_responder(severity="high_risk"), approved=True)
    await _kernel(fw, goal="clean build").invoke(
        plugin_name="shell", function_name="run", arguments=KernelArguments(command="rm -r build")
    )
    assert RAN == ["rm -r build"]
    assert approval.requests[0].tool_name == "shell-run"
