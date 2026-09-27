"""Exercise the real SDK and Cloudflare code paths offline through mock HTTP transports."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx2
import pytest

from jev_firewall import PolicyConfigError, PolicyEngine, ToolCall
from jev_firewall.jev import CloudflareJevClient, TypeSafeSDKClient, build_jev_client
from jev_firewall.policy import JevConfig
from jev_firewall.rubric import build_questions, build_state
from jev_firewall.verdict import Decision

from .conftest import make_policy

# Shape copied from https://docs.typesafe.ai/api (response body section).
DOC_RESPONSE: dict[str, Any] = {
    "model": "jev-1.13.0",
    "answers": {
        "severity": {
            "type": "choice",
            "choice": "high_risk",
            "confidence": 0.81,
            "probabilities": {
                "low_risk": 0.02,
                "moderate_risk": 0.08,
                "high_risk": 0.86,
                "critical_danger": 0.04,
            },
        },
        "is_irreversible": {"type": "noul", "noul": 0.93},
        "matches_stated_goal": {"type": "noul", "noul": 0.12},
    },
    "usage": {"input_tokens": 612, "output_tokens": 40},
}

STATE = build_state("terminal", {"command": "rm -r ./data"}, "Summarize the logs")
QUESTIONS = build_questions(include_goal=True)


def sdk_client(handler: Any, **kw: Any) -> TypeSafeSDKClient:
    return TypeSafeSDKClient(
        api_key="test-key",
        model="jev-1.13.0",
        timeout_s=kw.pop("timeout_s", 1.0),
        max_retries=kw.pop("max_retries", 0),
        transport=httpx2.MockTransport(handler),
        **kw,
    )


async def test_sdk_request_and_response_shape() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, json=DOC_RESPONSE, headers={"x-typesafe-request-id": "req_1"})

    client = sdk_client(handler)
    resp = await client.system_one(STATE, QUESTIONS)
    await client.aclose()

    req = seen[0]
    assert req.method == "POST"
    assert str(req.url) == "https://api.typesafe.ai/v1/systemone"
    assert req.headers["authorization"] == "Bearer test-key"
    body = json.loads(req.content)
    assert body["model"] == "jev-1.13.0"
    assert body["state"] == STATE
    assert body["questions"]["severity"]["criteria"]["critical_danger"]
    assert body["questions"]["is_irreversible"]["criteria"]["true"]

    assert resp.model == "jev-1.13.0"
    assert resp.choices["severity"].choice == "high_risk"
    assert resp.choices["severity"].confidence == pytest.approx(0.81)
    assert resp.nouls["is_irreversible"].noul == pytest.approx(0.93)
    assert resp.input_tokens == 612
    assert resp.request_id == "req_1"


async def test_sdk_gateway_base_url() -> None:
    urls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        urls.append(str(request.url))
        return httpx2.Response(200, json=DOC_RESPONSE)

    client = sdk_client(handler, base_url="https://openrouter.ai/api")
    await client.system_one(STATE, QUESTIONS)
    await client.aclose()
    assert urls == ["https://openrouter.ai/api/v1/systemone"]


async def test_sdk_retries_429_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx2.Response(429, json={"error": "slow down"})
        return httpx2.Response(200, json=DOC_RESPONSE)

    client = sdk_client(handler, max_retries=2)
    resp = await client.system_one(STATE, QUESTIONS)
    await client.aclose()
    assert calls["n"] == 2 and resp.choices["severity"].choice == "high_risk"


async def test_sdk_timeout_budget_is_hard() -> None:
    async def handler(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(2)
        return httpx2.Response(200, json=DOC_RESPONSE)

    from jev_firewall import JevUnavailable

    client = sdk_client(handler, timeout_s=0.2, max_retries=3)
    loop = asyncio.get_running_loop()
    start = loop.time()
    with pytest.raises(JevUnavailable):
        await client.system_one(STATE, QUESTIONS)
    assert loop.time() - start < 0.6
    await client.aclose()


@pytest.mark.parametrize(
    ("status", "fail_mode", "expected"),
    [(500, "closed", Decision.DENY), (401, "closed", Decision.DENY), (500, "open", Decision.ALLOW)],
)
def test_engine_with_sdk_errors(status: int, fail_mode: str, expected: Decision) -> None:
    client = sdk_client(lambda r: httpx2.Response(status, json={"error": "x"}))
    engine = PolicyEngine(make_policy(fail_mode=fail_mode), client)
    try:
        v = engine.evaluate(ToolCall("terminal", {"command": "ls"}, "list files"))
    finally:
        engine.close()
    assert v.decision is expected
    assert v.error and "TypeSafe" in v.error


def test_engine_end_to_end_with_documented_response() -> None:
    client = sdk_client(lambda r: httpx2.Response(200, json=DOC_RESPONSE))
    engine = PolicyEngine(make_policy(), client)
    try:
        v = engine.evaluate(ToolCall("terminal", {"command": "rm -r ./data"}, "Summarize the logs"))
    finally:
        engine.close()
    assert v.decision is Decision.HOLD
    assert "severity:high_risk->hold" in v.reasons
    assert "goal_mismatch:0.12->hold" in v.reasons
    assert v.assessment is not None and v.assessment.input_tokens == 612


async def test_cloudflare_wraps_payload_and_unwraps_result() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, json={"result": DOC_RESPONSE, "success": True}, headers={"cf-ray": "abc"})

    client = CloudflareJevClient(
        api_token="cf-token",
        account_id="acct123",
        model="typesafe/jev",
        timeout_s=1.0,
        max_retries=0,
        transport=httpx2.MockTransport(handler),
    )
    resp = await client.system_one(STATE, QUESTIONS)
    await client.aclose()
    req = seen[0]
    assert str(req.url) == "https://api.cloudflare.com/client/v4/accounts/acct123/ai/run"
    assert req.headers["authorization"] == "Bearer cf-token"
    body = json.loads(req.content)
    assert body["model"] == "typesafe/jev"
    assert body["input"]["state"] == STATE
    assert set(body["input"]["questions"]) == set(QUESTIONS)
    assert resp.choices["severity"].choice == "high_risk"
    assert resp.request_id == "abc"


async def test_cloudflare_retries_then_fails() -> None:
    from jev_firewall import JevUnavailable

    calls = {"n": 0}

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls["n"] += 1
        return httpx2.Response(503)

    client = CloudflareJevClient(
        api_token="t",
        account_id="a",
        model="typesafe/jev",
        timeout_s=1.0,
        max_retries=2,
        transport=httpx2.MockTransport(handler),
    )
    with pytest.raises(JevUnavailable, match="3 attempts"):
        await client.system_one(STATE, QUESTIONS)
    await client.aclose()
    assert calls["n"] == 3


def test_build_client_reads_route_specific_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts-key")
    cfg = JevConfig(route="openrouter", timeout_s=1, max_retries=0)
    with pytest.raises(PolicyConfigError, match="OPENROUTER_API_KEY"):
        build_jev_client(cfg)
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
    client = build_jev_client(cfg)
    assert isinstance(client, TypeSafeSDKClient) and client.model == "~typesafe/jev-latest"


def test_build_cloudflare_needs_account(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "t")
    monkeypatch.delenv("CLOUDFLARE_ACCOUNT_ID", raising=False)
    with pytest.raises(PolicyConfigError, match="CLOUDFLARE_ACCOUNT_ID"):
        build_jev_client(JevConfig(route="cloudflare", timeout_s=1, max_retries=0))
