"""LangGraph: every tool call in a ToolNode goes through the firewall first.

pip install "jev-firewall[langgraph]"
python examples/langgraph_minimal.py
"""

from __future__ import annotations

from _shared import make_firewall
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

from jev_firewall.adapters.langgraph import firewall_tool_node


@tool
def terminal(command: str) -> str:
    """Run a shell command (simulated)."""
    return f"(simulated) {command}"


def main() -> None:
    firewall = make_firewall()
    builder = StateGraph(MessagesState)
    builder.add_node("tools", firewall_tool_node([terminal], firewall, on_block="message"))
    builder.add_edge(START, "tools")
    graph = builder.compile()

    for i, command in enumerate(["git status", "rm -rf ~/*"]):
        call = {"name": "terminal", "args": {"command": command}, "id": f"call-{i}"}
        out = graph.invoke({"messages": [HumanMessage("Tidy up my repo"), AIMessage("", tool_calls=[call])]})
        print(f"{command!r:>14} -> {out['messages'][-1].content}")
    firewall.close()


if __name__ == "__main__":
    main()
