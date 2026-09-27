"""Framework-free helpers shared by adapters (never imported by the core package)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any


def first_user_text(messages: Iterable[Any] | None) -> str | None:
    """Text of the first user/human message in a list of message objects or dicts.

    Used as the default `agent_goal`. Only the user's own words count; tool output and
    retrieved content come later in the conversation and cannot rewrite the goal.
    """
    for m in messages or ():
        if isinstance(m, Mapping):
            role = m.get("role") or m.get("type")
            content = m.get("content")
        else:
            role = getattr(m, "role", None) or getattr(m, "type", None)
            content = getattr(m, "content", None)
        if role in ("human", "user"):
            return content_text(content)
    return None


def content_text(content: Any) -> str | None:
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence):
        parts = []
        for p in content:
            if isinstance(p, Mapping):
                parts.append(str(p.get("text") or ""))
            elif isinstance(p, str):
                parts.append(p)
            else:
                parts.append(str(getattr(p, "text", "") or ""))
        return " ".join(x for x in parts if x) or None
    return None
