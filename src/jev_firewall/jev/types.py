"""Transport-neutral Jev request/response types and the `JevClient` protocol."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class ChoiceResult:
    choice: str
    probabilities: Mapping[str, float]
    confidence: float


@dataclass(frozen=True)
class NoulResult:
    noul: float


@dataclass(frozen=True)
class JevResponse:
    model: str
    choices: Mapping[str, ChoiceResult] = field(default_factory=dict)
    nouls: Mapping[str, NoulResult] = field(default_factory=dict)
    input_tokens: int | None = None
    request_id: str | None = None
    latency_ms: float = 0.0

    @property
    def answer_keys(self) -> set[str]:
        return set(self.choices) | set(self.nouls)


@runtime_checkable
class JevClient(Protocol):
    """One call to Jev. Implementations own timeouts and retries and raise `JevUnavailable`
    on any failure; the engine turns that into a verdict using the explicit `fail_mode`."""

    async def system_one(
        self, state: Mapping[str, Any], questions: Mapping[str, Mapping[str, Any]]
    ) -> JevResponse: ...

    async def aclose(self) -> None: ...


def parse_wire_answers(body: Mapping[str, Any], *, latency_ms: float, request_id: str | None) -> JevResponse:
    """Parse the documented `/v1/systemone` JSON body (also used by the Cloudflare route)."""
    from jev_firewall.errors import JevUnavailable

    answers = body.get("answers")
    if not isinstance(answers, Mapping):
        raise JevUnavailable("Jev response has no 'answers' object")
    choices: dict[str, ChoiceResult] = {}
    nouls: dict[str, NoulResult] = {}
    try:
        for key, a in answers.items():
            kind = a.get("type")
            if kind == "choice":
                choices[key] = ChoiceResult(
                    choice=str(a["choice"]),
                    probabilities={str(k): float(v) for k, v in a.get("probabilities", {}).items()},
                    confidence=float(a["confidence"]),
                )
            elif kind == "noul":
                nouls[key] = NoulResult(noul=float(a["noul"]))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise JevUnavailable(f"malformed Jev answer: {exc!r}") from exc
    usage = body.get("usage") or {}
    tokens = usage.get("input_tokens") if isinstance(usage, Mapping) else None
    return JevResponse(
        model=str(body.get("model", "unknown")),
        choices=choices,
        nouls=nouls,
        input_tokens=int(tokens) if isinstance(tokens, int) else None,
        request_id=request_id,
        latency_ms=latency_ms,
    )
