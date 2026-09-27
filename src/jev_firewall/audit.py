"""Append-only JSONL audit trail of every firewall decision.

One line per event. Events for the same tool call share `call_id`:

- `verdict`   the engine's decision (always written)
- `approval`  how a HOLD was resolved, and by whom
- `outcome`   whether the tool ran, was blocked, or raised

Only redacted arguments are ever written.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TextIO

from jev_firewall.verdict import Verdict

EventType = Literal["verdict", "approval", "outcome"]


class AuditLog:
    def __init__(self, path: str | Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.fsync = fsync
        self._lock = threading.Lock()
        self._fh: TextIO | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: EventType, call_id: str, payload: Mapping[str, Any]) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
            "event": event,
            "call_id": call_id,
            **payload,
        }
        line = json.dumps(record, ensure_ascii=False, default=str, separators=(",", ":")) + "\n"
        with self._lock:
            # The handle stays open between writes: reopening per record cost ~1 ms on Windows.
            if self._fh is None or self._fh.closed:
                self._fh = self.path.open("a", encoding="utf-8")
            self._fh.write(line)
            self._fh.flush()
            if self.fsync:
                os.fsync(self._fh.fileno())

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def verdict(self, v: Verdict) -> None:
        data = v.to_dict()
        data.pop("call_id")
        self.write("verdict", v.call_id, data)

    def approval(
        self, call_id: str, *, approved: bool, resolver: str, note: str | None, wait_ms: float
    ) -> None:
        self.write(
            "approval",
            call_id,
            {"approved": approved, "resolver": resolver, "note": note, "wait_ms": round(wait_ms, 3)},
        )

    def outcome(
        self, call_id: str, *, status: Literal["executed", "blocked", "error"], detail: str | None = None
    ) -> None:
        self.write("outcome", call_id, {"status": status, "detail": detail})

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return read_audit(self.path)


def read_audit(path: str | Path) -> Iterator[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
