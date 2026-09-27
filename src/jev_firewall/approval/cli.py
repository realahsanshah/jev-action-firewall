"""Approve or reject held actions at the terminal."""

from __future__ import annotations

import asyncio
import getpass
import json
import sys
from collections.abc import Callable
from typing import TextIO

from jev_firewall.approval.base import ApprovalRequest, ApprovalResult


class CLIApproval:
    """Prints the held action and asks `y/N`. Anything but `y`/`yes` rejects.

    With `timeout_s`, no answer in time rejects (resolver `cli:timeout`). The blocked `input()`
    thread cannot be cancelled and is left to finish on its own.
    """

    def __init__(
        self,
        *,
        timeout_s: float | None = None,
        input_fn: Callable[[str], str] = input,
        out: TextIO | None = None,
    ) -> None:
        self.timeout_s = timeout_s
        self.input_fn = input_fn
        self.out = out

    async def request(self, req: ApprovalRequest) -> ApprovalResult:
        out = self.out or sys.stderr
        v = req.verdict
        a = v.assessment
        lines = [
            "",
            "=" * 64,
            f"jev-firewall HOLD  tool={req.tool_name}  call={req.call_id[:8]}",
            f"goal:    {req.agent_goal or '(none)'}",
            f"args:    {json.dumps(req.redacted_args, ensure_ascii=False)[:800]}",
        ]
        if a is not None:
            lines.append(
                f"jev:     severity={a.severity.value} (conf {a.severity_confidence:.2f})  "
                f"irreversible={a.irreversible:.2f}  goal_match="
                + ("n/a" if a.goal_match is None else f"{a.goal_match:.2f}")
            )
        lines.append(f"reasons: {'; '.join(v.reasons)}")
        lines.append("=" * 64)
        print("\n".join(lines), file=out, flush=True)
        prompt = "Approve this action? [y/N] "
        try:
            if self.timeout_s is None:
                answer = await asyncio.to_thread(self.input_fn, prompt)
            else:
                async with asyncio.timeout(self.timeout_s):
                    answer = await asyncio.to_thread(self.input_fn, prompt)
        except TimeoutError:
            print("\n(no answer, rejecting)", file=out, flush=True)
            return ApprovalResult(False, "cli:timeout", f"no answer within {self.timeout_s}s")
        except EOFError:
            return ApprovalResult(False, "cli:eof", "stdin closed")
        approved = answer.strip().lower() in {"y", "yes"}
        return ApprovalResult(approved, f"cli:{_user()}", answer.strip() or None)


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
