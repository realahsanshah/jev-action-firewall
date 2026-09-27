"""Standalone LangGraph project using the published package.

    pip install -r requirements.txt
    export TYPESAFE_API_KEY=...   # optional; without it the offline stand-in is used
    python app.py
"""

import os

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from jev_firewall import FakeJevClient, Firewall, PolicyEngine, TimeoutDenyApproval
from jev_firewall.adapters.langgraph import firewall_tool_node

live = bool(os.environ.get("TYPESAFE_API_KEY"))
engine = PolicyEngine.from_yaml("policy.yaml", jev=None if live else FakeJevClient())
firewall = Firewall(engine, TimeoutDenyApproval())
print("mode:", "live Jev" if live else "offline stand-in (not Jev)")


@tool
def terminal(command: str) -> str:
    """Run a shell command (simulated)."""
    return f"(simulated) {command}"


builder = StateGraph(MessagesState)
builder.add_node("tools", firewall_tool_node([terminal], firewall, on_block="message"))
builder.add_edge(START, "tools")
graph = builder.compile()

for i, command in enumerate(["git status", "rm -rf ~/"]):
    call = {"name": "terminal", "args": {"command": command}, "id": f"c{i}"}
    out = graph.invoke({"messages": [HumanMessage("Tidy up my repo"), AIMessage("", tool_calls=[call])]})
    print(f"{command!r:>14} -> {out['messages'][-1].content}")

firewall.close()
