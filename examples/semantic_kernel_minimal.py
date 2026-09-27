"""Semantic Kernel: a FUNCTION_INVOCATION filter in front of every kernel function.

pip install "jev-firewall[semantic_kernel]"
python examples/semantic_kernel_minimal.py
"""

from __future__ import annotations

import asyncio

from _shared import make_firewall
from semantic_kernel import Kernel
from semantic_kernel.filters import FilterTypes
from semantic_kernel.functions import KernelArguments, kernel_function

from jev_firewall.adapters.semantic_kernel import JevFunctionInvocationFilter


class Shell:
    @kernel_function(name="run", description="Run a shell command (simulated).")
    def run(self, command: str) -> str:
        return f"(simulated) {command}"


async def main() -> None:
    firewall = make_firewall()
    kernel = Kernel()
    kernel.add_plugin(Shell(), plugin_name="shell")
    kernel.add_filter(
        FilterTypes.FUNCTION_INVOCATION,
        JevFunctionInvocationFilter(firewall, goal="Tidy up my repo", on_block="result"),
    )
    for command in ["git log --oneline -5", "psql -c 'DROP DATABASE prod'"]:
        args = KernelArguments(command=command)
        result = await kernel.invoke(plugin_name="shell", function_name="run", arguments=args)
        print(f"{command!r:>32} -> {result}")
    await firewall.aclose()


if __name__ == "__main__":
    asyncio.run(main())
