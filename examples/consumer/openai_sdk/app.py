"""Standalone OpenAI Agents SDK project using the published package.

Uses the SDK's ScriptedModel so no OpenAI key is needed; replace it with a real model.

    pip install -r requirements.txt
    python app.py
"""

import asyncio
import os

from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.testing import ScriptedModel, assistant_message, function_call

from jev_firewall import FakeJevClient, Firewall, PolicyEngine, TimeoutDenyApproval
from jev_firewall.adapters.openai_agents import protect_tools

set_tracing_disabled(True)


@function_tool
def terminal(command: str) -> str:
    """Run a shell command (simulated)."""
    return f"(simulated) {command}"


async def main() -> None:
    live = bool(os.environ.get("TYPESAFE_API_KEY"))
    engine = PolicyEngine.from_yaml("policy.yaml", jev=None if live else FakeJevClient())
    firewall = Firewall(engine, TimeoutDenyApproval())
    print("mode:", "live Jev" if live else "offline stand-in (not Jev)")

    model = ScriptedModel(
        [
            [function_call("terminal", {"command": "sudo rm -rf /"}, call_id="c1")],
            [assistant_message("That command was blocked, so I stopped.")],
        ]
    )
    agent = Agent(name="ops", model=model, tools=protect_tools([terminal], firewall, on_block="reject"))
    result = await Runner.run(agent, "Free up disk space")
    for item in result.new_items:
        if getattr(item, "output", None):
            print("tool result seen by the model:", item.output)
    print("final:", result.final_output)
    await firewall.aclose()


asyncio.run(main())
