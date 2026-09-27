"""Standalone Google ADK project using the published package.

Uses a scripted model so no Gemini key is needed; replace it with a real model.

    pip install -r requirements.txt
    python app.py
"""

import asyncio
import os
from collections.abc import AsyncGenerator

from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from jev_firewall import FakeJevClient, Firewall, PolicyEngine, TimeoutDenyApproval
from jev_firewall.adapters.google_adk import JevFirewallPlugin


def terminal(command: str) -> dict[str, str]:
    """Run a shell command (simulated)."""
    return {"output": f"(simulated) {command}"}


class ScriptedLlm(BaseLlm):
    model: str = "scripted"

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        results = [p.function_response for c in llm_request.contents for p in (c.parts or []) if p.function_response]
        if results:
            text = f"tool said: {results[0].response}"
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))
            return
        call = types.FunctionCall(name="terminal", args={"command": "psql -c 'DROP DATABASE prod'"}, id="a1")
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=call)]))


async def main() -> None:
    live = bool(os.environ.get("TYPESAFE_API_KEY"))
    engine = PolicyEngine.from_yaml("policy.yaml", jev=None if live else FakeJevClient())
    firewall = Firewall(engine, TimeoutDenyApproval())
    print("mode:", "live Jev" if live else "offline stand-in (not Jev)")

    agent = LlmAgent(name="ops", model=ScriptedLlm(), tools=[terminal])
    runner = InMemoryRunner(app=App(name="demo", root_agent=agent, plugins=[JevFirewallPlugin(firewall)]))
    session = await runner.session_service.create_session(app_name="demo", user_id="u")
    msg = types.Content(role="user", parts=[types.Part(text="Clean up old databases")])
    async for event in runner.run_async(user_id="u", session_id=session.id, new_message=msg):
        for part in (event.content.parts if event.content else None) or []:
            if part.text:
                print("agent:", part.text)
    await firewall.aclose()


asyncio.run(main())
