"""Google ADK: a runner-wide plugin checks every tool call.

Uses a scripted BaseLlm so it runs without a Gemini key; swap in a real model for use.

    pip install "jev-firewall[google_adk]"
    python examples/google_adk_minimal.py
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

from _shared import make_firewall
from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from jev_firewall.adapters.google_adk import JevFirewallPlugin


def terminal(command: str) -> dict[str, str]:
    """Run a shell command (simulated)."""
    return {"output": f"(simulated) {command}"}


class ScriptedLlm(BaseLlm):
    model: str = "scripted"

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        results = [
            p.function_response for c in llm_request.contents for p in (c.parts or []) if p.function_response
        ]
        if results:
            text = f"tool said: {results[0].response}"
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))
            return
        call = types.FunctionCall(name="terminal", args={"command": "mkfs.ext4 /dev/sda1"}, id="adk1")
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=call)]))


async def main() -> None:
    firewall = make_firewall()
    agent = LlmAgent(name="ops", model=ScriptedLlm(), tools=[terminal])
    runner = InMemoryRunner(app=App(name="demo", root_agent=agent, plugins=[JevFirewallPlugin(firewall)]))
    session = await runner.session_service.create_session(app_name="demo", user_id="u")
    msg = types.Content(role="user", parts=[types.Part(text="Reset the test environment")])
    async for event in runner.run_async(user_id="u", session_id=session.id, new_message=msg):
        for part in (event.content.parts if event.content else None) or []:
            if part.text:
                print("agent:", part.text)
    await firewall.aclose()


if __name__ == "__main__":
    asyncio.run(main())
