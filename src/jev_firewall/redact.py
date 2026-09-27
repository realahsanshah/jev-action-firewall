"""Strip secrets and PII from tool arguments before anything is sent to Jev or the audit log.

Redacted values become `"[REDACTED:<kind>]"` so Jev can still see that a secret was present
(which is itself a risk signal) without seeing the secret.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from jev_firewall.policy import RedactionConfig

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_\-.])(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|x-api-key|"
    r"authorization|auth|cookie|set-cookie|private[_-]?key|credentials?|access[_-]?key|"
    r"secret[_-]?key|client[_-]?secret|session[_-]?(?:id|token)|ssn|cvv|card[_-]?number)$"
)

# (kind, pattern, replacement). Order matters: more specific patterns first.
_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED:private_key]",
    ),
    (
        "url_credentials",
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^:/\s@]+):[^@/\s]+@"),
        r"\1:[REDACTED:password]@",
    ),
    ("bearer_token", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-~+/=]{8,}"), r"\1 [REDACTED:token]"),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"), "[REDACTED:api_key]"),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), "[REDACTED:api_key]"),
    ("stripe_key", re.compile(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}"), "[REDACTED:api_key]"),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})"),
        "[REDACTED:token]",
    ),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"), "[REDACTED:token]"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:api_key]"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED:api_key]"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        "[REDACTED:token]",
    ),
    (
        "inline_secret",
        re.compile(
            r"(?i)\b((?:[A-Z0-9_]*_)?(?:password|passwd|pwd|secret|token|api[_-]?key|apikey)"
            r"\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&|]+)"
        ),
        r"\1[REDACTED:secret]",
    ),
)

_PII_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # Keep the email domain: "is this going to an outside domain?" is a real risk signal.
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"), r"[REDACTED:email]@\1"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:ssn]"),
    (
        "phone",
        re.compile(r"(?<![\w-])(?:\+\d{1,3}[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}(?![\w-])"),
        "[REDACTED:phone]",
    ),
)

_CARD = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass
class RedactionReport:
    kinds: set[str] = field(default_factory=set)
    truncated: bool = False


class Redactor:
    """Recursively redacts and bounds a JSON-like value."""

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self.config = config or RedactionConfig()
        self._extra_keys = tuple(re.compile(p, re.IGNORECASE) for p in self.config.extra_key_patterns)

    def redact_args(self, args: Mapping[str, Any]) -> tuple[dict[str, Any], RedactionReport]:
        report = RedactionReport()
        out = self._walk(dict(args), report, depth=0)
        assert isinstance(out, dict)
        return out, report

    def redact_goal(self, goal: str | None) -> str | None:
        if goal is None:
            return None
        one_line = " ".join(goal.split())
        if not one_line:
            return None
        text = self.redact_text(one_line, RedactionReport())
        limit = self.config.max_goal_chars
        return text if len(text) <= limit else text[: limit - 1] + "…"

    def redact_text(self, text: str, report: RedactionReport) -> str:
        for kind, rx, repl in _VALUE_PATTERNS:
            text, n = rx.subn(repl, text)
            if n:
                report.kinds.add(kind)
        if self.config.redact_pii:
            text = self._redact_cards(text, report)
            for kind, rx, repl in _PII_PATTERNS:
                text, n = rx.subn(repl, text)
                if n:
                    report.kinds.add(kind)
        return text

    def _redact_cards(self, text: str, report: RedactionReport) -> str:
        def repl(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                report.kinds.add("card_number")
                return "[REDACTED:card_number]"
            return m.group(0)

        return _CARD.sub(repl, text)

    def _sensitive_key(self, key: str) -> bool:
        return bool(_SENSITIVE_KEY.search(key)) or any(rx.search(key) for rx in self._extra_keys)

    def _walk(self, value: Any, report: RedactionReport, depth: int) -> Any:
        cfg = self.config
        if depth > cfg.max_depth:
            report.truncated = True
            return "[TRUNCATED:depth]"
        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= cfg.max_items:
                    report.truncated = True
                    out["…"] = f"[TRUNCATED:{len(value) - i} more keys]"
                    break
                key = str(k)
                if self._sensitive_key(key) and v not in (None, "", False):
                    report.kinds.add("sensitive_key")
                    out[key] = "[REDACTED:secret]"
                else:
                    out[key] = self._walk(v, report, depth + 1)
            return out
        if isinstance(value, (str, bytes)):
            text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
            text = self.redact_text(text, report)
            if len(text) > cfg.max_string_chars:
                report.truncated = True
                text = text[: cfg.max_string_chars] + f"…[truncated {len(text) - cfg.max_string_chars} chars]"
            return text
        if isinstance(value, Sequence):
            items = [self._walk(v, report, depth + 1) for v in list(value)[: cfg.max_items]]
            if len(value) > cfg.max_items:
                report.truncated = True
                items.append(f"[TRUNCATED:{len(value) - cfg.max_items} more items]")
            return items
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self._walk(repr(value), report, depth)


def flatten_strings(value: Any, *, _depth: int = 0) -> str:
    """All string-ish leaves of a JSON-like value joined by newlines, for hard-pattern matching."""
    if _depth > 20:
        return ""
    if isinstance(value, Mapping):
        return "\n".join(f"{k}\n{flatten_strings(v, _depth=_depth + 1)}" for k, v in value.items())
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, Sequence):
        return "\n".join(flatten_strings(v, _depth=_depth + 1) for v in value)
    return "" if value is None else str(value)
