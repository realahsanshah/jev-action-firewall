from __future__ import annotations

import json

import pytest

from jev_firewall.policy import RedactionConfig
from jev_firewall.redact import Redactor, flatten_strings

SECRETS = {
    "openai": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
    "anthropic": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_" + "a" * 36,
    "stripe": "sk_live_" + "b" * 24,
    "slack": "xoxb-1234567890-abcdefghij",
    "google": "AIza" + "c" * 35,
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
}


@pytest.mark.parametrize(("kind", "secret"), list(SECRETS.items()))
def test_value_secrets_are_redacted(kind: str, secret: str) -> None:
    out, report = Redactor().redact_args({"command": f"deploy --credential {secret} now"})
    assert secret not in json.dumps(out), kind
    assert "[REDACTED:" in out["command"]
    assert report.kinds


def test_sensitive_keys_are_redacted_whole() -> None:
    args = {
        "password": "hunter2",
        "api_key": "whatever",
        "Authorization": "Bearer abc",
        "db": {"client_secret": "s3cr3t", "host": "db.internal"},
        "max_tokens": 512,
        "token_count": 3,
    }
    out, _ = Redactor().redact_args(args)
    assert out["password"] == out["api_key"] == out["Authorization"] == "[REDACTED:secret]"
    assert out["db"]["client_secret"] == "[REDACTED:secret]"
    assert out["db"]["host"] == "db.internal"
    assert out["max_tokens"] == 512
    assert out["token_count"] == 3


def test_inline_and_url_credentials() -> None:
    out, _ = Redactor().redact_args(
        {
            "cmd": "export API_KEY=abc123xyz && psql postgres://admin:pa55w0rd@db:5432/app",
            "hdr": "curl -H 'Authorization: Bearer abcdefghijklmnop1234' https://x",
        }
    )
    assert "abc123xyz" not in out["cmd"]
    assert "pa55w0rd" not in out["cmd"]
    assert "postgres://admin:[REDACTED:password]@db" in out["cmd"]
    assert "abcdefghijklmnop1234" not in out["hdr"]


def test_private_key_block() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----"
    out, _ = Redactor().redact_args({"content": f"key:\n{pem}\n"})
    assert "MIIEow" not in out["content"]


def test_pii_keeps_email_domain() -> None:
    out, _ = Redactor().redact_args(
        {
            "to": "jane.doe@evil-corp.io",
            "body": "call 415-555-0132, ssn 123-45-6789, card 4111 1111 1111 1111",
        }
    )
    assert out["to"] == "[REDACTED:email]@evil-corp.io"
    assert "415-555-0132" not in out["body"]
    assert "123-45-6789" not in out["body"]
    assert "4111" not in out["body"]


def test_non_luhn_numbers_survive() -> None:
    out, _ = Redactor().redact_args({"order": "order 1234567890123 shipped"})
    assert "1234567890123" in out["order"]


def test_pii_can_be_disabled() -> None:
    out, _ = Redactor(RedactionConfig(redact_pii=False)).redact_args({"to": "a@b.com"})
    assert out["to"] == "a@b.com"


def test_truncation_and_bounds() -> None:
    r = Redactor(RedactionConfig(max_string_chars=40, max_items=3, max_depth=2))
    out, report = r.redact_args({"s": "x" * 100, "l": list(range(10)), "deep": {"a": {"b": {"c": 1}}}})
    assert out["s"].startswith("x" * 40) and "truncated 60 chars" in out["s"]
    assert out["l"][:3] == [0, 1, 2] and "7 more" in out["l"][3]
    assert out["deep"]["a"]["b"] == "[TRUNCATED:depth]"
    assert report.truncated


def test_goal_is_single_line_bounded_and_redacted() -> None:
    r = Redactor(RedactionConfig(max_goal_chars=30))
    goal = r.redact_goal("Email the report\n to bob@example.com with key sk-proj-" + "a" * 30)
    assert goal is not None and "\n" not in goal and len(goal) <= 30
    assert Redactor().redact_goal("   ") is None
    assert "sk-proj" not in (Redactor().redact_goal("use sk-proj-" + "a" * 30) or "")


def test_non_json_values_become_strings() -> None:
    out, _ = Redactor().redact_args({"obj": object(), "b": b"bytes"})
    assert isinstance(out["obj"], str) and out["b"] == "bytes"


def test_flatten_strings() -> None:
    assert "rm -rf /" in flatten_strings({"a": [{"cmd": "rm -rf /"}], "n": 1})
