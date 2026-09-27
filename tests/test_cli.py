from __future__ import annotations

import json
from pathlib import Path

import pytest

from jev_firewall import AuditLog, FakeJevClient, PolicyEngine, ToolCall
from jev_firewall.cli import main

from .conftest import ROOT, make_policy

POLICY = str(ROOT / "policy.example.yaml")


def test_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", POLICY, "--tool", "read_file", "--tool", "terminal"]) == 0
    out = capsys.readouterr().out
    assert "fail_mode: closed" in out
    assert "read_file: rule=read_* action=allow" in out


def test_check_invalid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("version: 1\n", encoding="utf-8")
    assert main(["check", str(bad)]) == 2
    assert "invalid policy" in capsys.readouterr().err


def test_eval_offline_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["eval", POLICY, "--tool", "read_file", "--args", '{"path": "a"}', "--offline"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "allow"
    code = main(["eval", POLICY, "--tool", "terminal", "--args", '{"command": "rm -rf /"}', "--offline"])
    assert code == 20
    assert json.loads(capsys.readouterr().out)["decision"] == "deny"


def test_audit_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    with PolicyEngine(make_policy(), FakeJevClient(), audit=log) as engine:
        engine.evaluate(ToolCall("terminal", {"command": "rm -rf /"}, "x"))
        engine.evaluate(ToolCall("read_file", {"path": "a"}, "x"))
    assert main(["audit", str(log.path)]) == 0
    out = capsys.readouterr().out
    assert "2 decisions: allow=1, hold=0, deny=1" in out
