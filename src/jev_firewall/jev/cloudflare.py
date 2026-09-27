"""Jev on Cloudflare Workers AI (`typesafe/jev`).

Cloudflare's REST route is not SDK-compatible: the URL carries an account id and the body
wraps the TypeSafe payload as `{"model": ..., "input": {"state", "questions"}}`. The question
and answer schemas are the same as TypeSafe's. See
https://developers.cloudflare.com/ai/models/typesafe/jev/.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Mapping
from typing import Any

import httpx2

from jev_firewall.errors import JevUnavailable
from jev_firewall.jev.types import JevResponse, parse_wire_answers

_RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 529})


class CloudflareJevClient:
    def __init__(
        self,
        *,
        api_token: str,
        account_id: str,
        model: str,
        timeout_s: float,
        max_retries: int,
        base_url: str = "https://api.cloudflare.com/client/v4",
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self._url = f"{base_url.rstrip('/')}/accounts/{account_id}/ai/run"
        self._http = httpx2.AsyncClient(
            timeout=timeout_s,
            transport=transport,
            headers={"Authorization": f"Bearer {api_token}"},
        )

    async def system_one(
        self, state: Mapping[str, Any], questions: Mapping[str, Mapping[str, Any]]
    ) -> JevResponse:
        payload = {"model": self.model, "input": {"state": dict(state), "questions": dict(questions)}}
        start = time.perf_counter()
        try:
            async with asyncio.timeout(self.timeout_s):
                body, request_id = await self._post_with_retries(payload)
        except TimeoutError as exc:
            raise JevUnavailable(f"Jev (cloudflare) exceeded {self.timeout_s:.3f}s budget") from exc
        latency_ms = (time.perf_counter() - start) * 1000
        inner = body.get("result", body) if isinstance(body.get("result"), Mapping) else body
        return parse_wire_answers(inner, latency_ms=latency_ms, request_id=request_id)

    async def _post_with_retries(self, payload: dict[str, Any]) -> tuple[Mapping[str, Any], str | None]:
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if attempt:
                await asyncio.sleep(min(0.2, 0.05 * 2 ** (attempt - 1)) * (0.75 + random.random() / 4))
            try:
                r = await self._http.post(self._url, json=payload)
            except httpx2.TransportError as exc:
                last = exc
                continue
            if r.status_code in _RETRY_STATUSES:
                last = JevUnavailable(f"Jev (cloudflare) HTTP {r.status_code}")
                continue
            if r.status_code >= 400:
                raise JevUnavailable(f"Jev (cloudflare) HTTP {r.status_code}: {r.text[:300]}")
            try:
                body = r.json()
            except ValueError as exc:
                raise JevUnavailable("Jev (cloudflare) returned non-JSON body") from exc
            if not isinstance(body, Mapping):
                raise JevUnavailable("Jev (cloudflare) returned a non-object body")
            return body, r.headers.get("cf-ray")
        raise JevUnavailable(f"Jev (cloudflare) failed after {self.max_retries + 1} attempts: {last}")

    async def aclose(self) -> None:
        await self._http.aclose()
