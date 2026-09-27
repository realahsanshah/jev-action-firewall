"""OpenAI Agents SDK: a tool input guardrail on every function tool.

Uses the SDK's ScriptedModel so it runs without an OpenAI key; swap in a real model for use.

    pip install "jev-firewall[openai_sdk]"
    python examples/openai_agents_minimal.py
"""

from __future__ import annotations

import asyncio

from _shared import make_firewall
from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.testing import ScriptedModel, assistant_message, function_call

from jev_firewall.adapters.openai_agents import protect_tools

set_tracing_disabled(True)


@function_tool
def terminal(command: str) -> str:
    """Run a shell command (simulated)."""
    return f"(simulated) {command}"


async def main() -> None:
    firewall = make_firewall()
    model = ScriptedModel(
        [
            [function_call("terminal", {"command": "sudo rm -rf / --no-preserve-root"}, call_id="c1")],
            [assistant_message("I was stopped from doing that.")],
        ]
    )
    agent = Agent(name="ops", model=model, tools=protect_tools([terminal], firewall, on_block="reject"))
    result = await Runner.run(agent, "Free up disk space")
    for item in result.new_items:
        if getattr(item, "output", None):
            print("tool result seen by the model:", item.output)
    print("final:", result.final_output)
    await firewall.aclose()


if __name__ == "__main__":
    asyncio.run(main())
