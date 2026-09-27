"""Jev access: one `JevClient` protocol over the direct API and the gateway routes."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx2

from jev_firewall.errors import PolicyConfigError
from jev_firewall.jev.cloudflare import CloudflareJevClient
from jev_firewall.jev.fake import FakeJevClient, fixed_responder, heuristic_responder
from jev_firewall.jev.sdk_backend import TypeSafeSDKClient
from jev_firewall.jev.types import ChoiceResult, JevClient, JevResponse, NoulResult
from jev_firewall.policy import JevConfig, JevRoute

__all__ = [
    "ROUTE_DEFAULTS",
    "ChoiceResult",
    "CloudflareJevClient",
    "FakeJevClient",
    "JevClient",
    "JevResponse",
    "NoulResult",
    "RouteDefaults",
    "TypeSafeSDKClient",
    "build_jev_client",
    "fixed_responder",
    "heuristic_responder",
]


@dataclass(frozen=True)
class RouteDefaults:
    model: str
    api_key_env: str
    base_url: str | None
    account_id_env: str | None = None


# Values from docs.typesafe.ai/sdk/python/usage and developers.cloudflare.com/ai/models/typesafe/jev.
ROUTE_DEFAULTS: dict[JevRoute, RouteDefaults] = {
    "direct": RouteDefaults("jev-1.13.0", "TYPESAFE_API_KEY", None),
    "openrouter": RouteDefaults("~typesafe/jev-latest", "OPENROUTER_API_KEY", "https://openrouter.ai/api"),
    "vercel": RouteDefaults("typesafe-ai/jev", "AI_GATEWAY_API_KEY", "https://ai-gateway.vercel.sh/typesafe"),
    "cloudflare": RouteDefaults(
        "typesafe/jev",
        "CLOUDFLARE_API_TOKEN",
        "https://api.cloudflare.com/client/v4",
        "CLOUDFLARE_ACCOUNT_ID",
    ),
}


def build_jev_client(config: JevConfig, *, transport: httpx2.AsyncBaseTransport | None = None) -> JevClient:
    """Build the client for `config.route`. Keys are read from the route's env var only, so a
    TypeSafe key is never sent to a gateway by accident."""
    d = ROUTE_DEFAULTS[config.route]
    key_env = config.api_key_env or d.api_key_env
    api_key = os.environ.get(key_env, "").strip()
    if not api_key:
        raise PolicyConfigError(f"jev.route={config.route!r} needs an API key in ${key_env}")
    model = config.model or d.model
    base_url = config.base_url or d.base_url
    if config.route == "cloudflare":
        acct_env = config.account_id_env or d.account_id_env or "CLOUDFLARE_ACCOUNT_ID"
        account_id = os.environ.get(acct_env, "").strip()
        if not account_id:
            raise PolicyConfigError(f"jev.route='cloudflare' needs an account id in ${acct_env}")
        return CloudflareJevClient(
            api_token=api_key,
            account_id=account_id,
            model=model,
            timeout_s=config.timeout_s,
            max_retries=config.max_retries,
            base_url=base_url or "https://api.cloudflare.com/client/v4",
            transport=transport,
        )
    return TypeSafeSDKClient(
        api_key=api_key,
        model=model,
        timeout_s=config.timeout_s,
        max_retries=config.max_retries,
        base_url=base_url,
        transport=transport,
    )
