"""Jev over the official `typesafe-sdk`: TypeSafe direct, OpenRouter, and Vercel AI Gateway.

The gateway routes are the SDK pointed at a different `base_url`, as documented at
https://docs.typesafe.ai/sdk/python/usage#configuring-the-base-url.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from typing import Any

import httpx2
from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy, SystemOneResponse, TypeSafeError

from jev_firewall.errors import JevUnavailable
from jev_firewall.jev.types import ChoiceResult, JevResponse, NoulResult


class TypeSafeSDKClient:
    """`JevClient` backed by `typesafe_sdk.AsyncTypeSafeClient`.

    `timeout_s` is the total budget for one decision, retries included. It is enforced three
    ways: as the SDK's per-request timeout, as the SDK `RetryPolicy` budget, and as a hard
    `asyncio.timeout` around the whole call.
    """

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_s: float,
        max_retries: int,
        base_url: str | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self.timeout_s = timeout_s
        self._client = AsyncTypeSafeClient(
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=timeout_s,
            transport=transport,
            retry=RetryPolicy(
                max_retries=max_retries,
                backoff_initial=min(0.05, timeout_s / 10),
                backoff_max=min(0.2, timeout_s / 4),
                timeout=timeout_s,
            ),
        )

    async def system_one(
        self, state: Mapping[str, Any], questions: Mapping[str, Mapping[str, Any]]
    ) -> JevResponse:
        start = time.perf_counter()
        try:
            async with asyncio.timeout(self.timeout_s):
                resp = await self._client.system_one(dict(state), dict(questions))  # type: ignore[arg-type]
        except TimeoutError as exc:
            raise JevUnavailable(f"Jev call exceeded {self.timeout_s:.3f}s budget") from exc
        except TypeSafeError as exc:
            raise JevUnavailable(f"Jev call failed: {type(exc).__name__}: {exc}") from exc
        latency_ms = (time.perf_counter() - start) * 1000
        return JevResponse(
            model=resp.model,
            choices={
                k: ChoiceResult(choice=a.choice, probabilities=dict(a.probabilities), confidence=a.confidence)
                for k, a in resp.choices.items()
            },
            nouls={k: NoulResult(noul=a.noul) for k, a in resp.nouls.items()},
            input_tokens=resp.usage.input_tokens,
            request_id=_request_id(resp),
            latency_ms=latency_ms,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def _request_id(resp: SystemOneResponse) -> str | None:
    # The SDK raises when `x-typesafe-request-id` is absent, which gateways may not forward.
    try:
        return resp.request_id
    except TypeSafeError:
        return None
