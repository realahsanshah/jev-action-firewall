"""Policy configuration: `policy.yaml` schema, loader, and per-tool risk threshold resolution."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from jev_firewall.errors import PolicyConfigError
from jev_firewall.verdict import Decision, SeverityTier

FailMode = Literal["open", "closed"]
JevRoute = Literal["direct", "openrouter", "vercel", "cloudflare"]
RuleAction = Literal["evaluate", "allow", "hold", "deny"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HardPattern(_Strict):
    """A regex over the tool's raw (pre-redaction) string arguments that sets a decision floor.

    Hard patterns run locally and never reach Jev. They exist because model answers can be
    steered by adversarial text inside the arguments; a pattern hit cannot be argued away.
    """

    pattern: str
    floor: Literal["hold", "deny"]
    description: str = ""
    ignore_case: bool = True

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regex {value!r}: {exc}") from exc
        return value

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE if self.ignore_case else 0)


Thresholds = dict[SeverityTier, Decision]


class DefaultsConfig(_Strict):
    thresholds: Thresholds
    irreversible_threshold: float = Field(ge=0.0, le=1.0)
    goal_match_threshold: float = Field(ge=0.0, le=1.0)
    min_confidence: float = Field(ge=0.0, le=1.0)
    hard_patterns: tuple[HardPattern, ...] = ()

    @field_validator("thresholds")
    @classmethod
    def _all_tiers(cls, value: Thresholds) -> Thresholds:
        missing = [t.value for t in SeverityTier if t not in value]
        if missing:
            raise ValueError(f"defaults.thresholds must map every tier; missing {missing}")
        return value


class ToolRule(_Strict):
    """Per-tool (or per-glob) overrides. Unset fields inherit from `defaults`."""

    action: RuleAction = "evaluate"
    thresholds: Thresholds = Field(default_factory=dict)
    fail_mode: FailMode | None = None
    allow_irreversible: bool = False
    irreversible_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    goal_match_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    hard_patterns: tuple[HardPattern, ...] = ()


class JevConfig(_Strict):
    """How to reach Jev. `model`/`api_key_env`/`base_url` default per route (see README)."""

    route: JevRoute
    timeout_s: float = Field(gt=0.0)
    max_retries: int = Field(ge=0, le=5)
    model: str | None = None
    api_key_env: str | None = None
    base_url: str | None = None
    account_id_env: str | None = None


class ApprovalConfig(_Strict):
    channel: Literal["cli", "webhook", "timeout_deny"]
    timeout_s: float | None = Field(default=None, gt=0.0)
    webhook_url: str | None = None

    @model_validator(mode="after")
    def _webhook_needs_url(self) -> ApprovalConfig:
        if self.channel == "webhook" and not self.webhook_url:
            raise ValueError("approval.webhook_url is required when channel is 'webhook'")
        return self


class AuditConfig(_Strict):
    path: str
    fsync: bool = False


class RedactionConfig(_Strict):
    max_string_chars: int = Field(default=500, ge=32)
    max_items: int = Field(default=50, ge=1)
    max_depth: int = Field(default=6, ge=1)
    max_goal_chars: int = Field(default=200, ge=20)
    extra_key_patterns: tuple[str, ...] = ()
    redact_pii: bool = True


class Policy(_Strict):
    """The full contents of `policy.yaml`. `fail_mode` and `jev` have no defaults on purpose."""

    version: Literal[1]
    fail_mode: FailMode
    jev: JevConfig
    defaults: DefaultsConfig
    tools: dict[str, ToolRule] = Field(default_factory=dict)
    approval: ApprovalConfig | None = None
    audit: AuditConfig | None = None
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except OSError as exc:
            raise PolicyConfigError(f"cannot read policy file {path}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise PolicyConfigError(f"policy file {path} is not valid YAML: {exc}") from exc
        return cls.from_mapping(raw, source=str(path))

    @classmethod
    def from_mapping(cls, raw: Any, *, source: str = "<mapping>") -> Policy:
        if not isinstance(raw, Mapping):
            raise PolicyConfigError(f"{source}: top level must be a mapping")
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise PolicyConfigError(f"{source}: invalid policy\n{exc}") from exc


@dataclass(frozen=True)
class ResolvedRule:
    """Effective settings for one tool after merging its matching rule over the defaults."""

    matched: str | None
    action: RuleAction
    thresholds: Mapping[SeverityTier, Decision]
    fail_mode: FailMode
    allow_irreversible: bool
    irreversible_threshold: float
    goal_match_threshold: float
    min_confidence: float
    hard_patterns: tuple[tuple[HardPattern, re.Pattern[str]], ...]

    def hard_floor(self, haystack: str) -> tuple[Decision | None, tuple[str, ...]]:
        """Strictest floor among hard patterns matching `haystack`, with reasons."""
        floor: Decision | None = None
        reasons: list[str] = []
        for spec, rx in self.hard_patterns:
            if rx.search(haystack):
                d = Decision(spec.floor)
                floor = d if floor is None else floor.at_least(d)
                reasons.append(f"hard_pattern:{spec.description or spec.pattern}->{spec.floor}")
        return floor, tuple(reasons)


class RiskThresholds:
    """Maps a tool name to its effective rule: exact name first, then the most specific glob.

    Glob specificity is the number of literal (non-wildcard) characters; ties go to the rule
    declared first in `policy.yaml`.
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._exact = {k: v for k, v in policy.tools.items() if not _is_glob(k)}
        self._globs = [(k, v) for k, v in policy.tools.items() if _is_glob(k)]
        self._cache: dict[str, ResolvedRule] = {}
        self._default_patterns = tuple((p, p.compiled()) for p in policy.defaults.hard_patterns)

    def resolve(self, tool_name: str) -> ResolvedRule:
        cached = self._cache.get(tool_name)
        if cached is not None:
            return cached
        key, rule = self._match(tool_name)
        d = self._policy.defaults
        r = rule or ToolRule()
        resolved = ResolvedRule(
            matched=key,
            action=r.action,
            thresholds={**d.thresholds, **r.thresholds},
            fail_mode=r.fail_mode or self._policy.fail_mode,
            allow_irreversible=r.allow_irreversible,
            irreversible_threshold=_pick(r.irreversible_threshold, d.irreversible_threshold),
            goal_match_threshold=_pick(r.goal_match_threshold, d.goal_match_threshold),
            min_confidence=_pick(r.min_confidence, d.min_confidence),
            hard_patterns=self._default_patterns + tuple((p, p.compiled()) for p in r.hard_patterns),
        )
        self._cache[tool_name] = resolved
        return resolved

    def _match(self, tool_name: str) -> tuple[str | None, ToolRule | None]:
        if tool_name in self._exact:
            return tool_name, self._exact[tool_name]
        best: tuple[int, str, ToolRule] | None = None
        for key, rule in self._globs:
            if fnmatch.fnmatchcase(tool_name, key):
                score = sum(1 for c in key if c not in "*?[]")
                if best is None or score > best[0]:
                    best = (score, key, rule)
        return (best[1], best[2]) if best else (None, None)


def _is_glob(key: str) -> bool:
    return any(c in key for c in "*?[")


def _pick(override: float | None, default: float) -> float:
    return default if override is None else override
