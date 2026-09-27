"""Standalone Semantic Kernel project using the published package.

    pip install -r requirements.txt
    python app.py
"""

import asyncio
import os

from semantic_kernel import Kernel
from semantic_kernel.filters import FilterTypes
from semantic_kernel.functions import KernelArguments, kernel_function

from jev_firewall import FakeJevClient, Firewall, PolicyEngine, TimeoutDenyApproval
from jev_firewall.adapters.semantic_kernel import JevFunctionInvocationFilter


class Shell:
    @kernel_function(name="run", description="Run a shell command (simulated).")
    def run(self, command: str) -> str:
        return f"(simulated) {command}"


async def main() -> None:
    live = bool(os.environ.get("TYPESAFE_API_KEY"))
    engine = PolicyEngine.from_yaml("policy.yaml", jev=None if live else FakeJevClient())
    firewall = Firewall(engine, TimeoutDenyApproval())
    print("mode:", "live Jev" if live else "offline stand-in (not Jev)")

    kernel = Kernel()
    kernel.add_plugin(Shell(), plugin_name="shell")
    kernel.add_filter(
        FilterTypes.FUNCTION_INVOCATION,
        JevFunctionInvocationFilter(firewall, goal="Tidy up my repo", on_block="result"),
    )
    for command in ["git log --oneline -5", "rm -rf ~/"]:
        result = await kernel.invoke(
            plugin_name="shell", function_name="run", arguments=KernelArguments(command=command)
        )
        print(f"{command!r:>24} -> {result}")
    await firewall.aclose()


asyncio.run(main())
