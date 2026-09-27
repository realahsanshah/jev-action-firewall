"""Resolve held actions through an HTTP webhook (Slack bot, internal approvals service, ...).

Protocol:

1. `POST {url}` with the JSON from `ApprovalRequest.to_dict()`.
2. The service answers either with a decision right away,
   `{"approved": true|false, "resolver": "slack:alice", "note": "..."}`,
   or with `{"status": "pending", "poll_url": "https://..."}`.
3. When pending, `GET poll_url` every `poll_interval_s` until it returns a decision.

No decision within `timeout_s` (or any HTTP/parse error) rejects the action.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import httpx2

from jev_firewall.approval.base import ApprovalRequest, ApprovalResult


class WebhookApproval:
    def __init__(
        self,
        url: str,
        *,
        timeout_s: float,
        poll_interval_s: float = 2.0,
        headers: Mapping[str, str] | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url
        self.timeout_s = timeout_s
        self.poll_interval_s = poll_interval_s
        self.headers = dict(headers or {})
        self._transport = transport

    async def request(self, req: ApprovalRequest) -> ApprovalResult:
        try:
            async with (
                asyncio.timeout(self.timeout_s),
                httpx2.AsyncClient(headers=self.headers, transport=self._transport, timeout=10.0) as http,
            ):
                r = await http.post(self.url, json=req.to_dict())
                r.raise_for_status()
                body = r.json()
                while True:
                    decided = _decision(body)
                    if decided is not None:
                        return decided
                    poll_url = body.get("poll_url") if isinstance(body, Mapping) else None
                    if not poll_url:
                        return ApprovalResult(False, "webhook:error", "pending response without poll_url")
                    await asyncio.sleep(self.poll_interval_s)
                    r = await http.get(str(poll_url))
                    r.raise_for_status()
                    body = r.json()
        except TimeoutError:
            return ApprovalResult(False, "webhook:timeout", f"no decision within {self.timeout_s}s")
        except (httpx2.HTTPError, ValueError) as exc:
            return ApprovalResult(False, "webhook:error", f"{type(exc).__name__}: {exc}")


def _decision(body: Any) -> ApprovalResult | None:
    if not isinstance(body, Mapping) or not isinstance(body.get("approved"), bool):
        return None
    return ApprovalResult(
        approved=body["approved"],
        resolver=str(body.get("resolver") or "webhook"),
        note=None if body.get("note") is None else str(body["note"]),
    )
