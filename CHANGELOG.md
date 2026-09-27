# Changelog

## [0.1.0](https://github.com/realahsanshah/jev-action-firewall/releases/tag/v0.1.0) (2026-09-27)

First release.

- `PolicyEngine`: evaluates each tool call with one Jev request (severity Choice,
  `is_irreversible` Noul, `matches_stated_goal` Noul) over a minimal, redacted state, and maps
  the answers to ALLOW / HOLD / DENY through per-tool `RiskThresholds` from `policy.yaml`.
- Deterministic hard-pattern floors that run locally before Jev and can't be argued away by
  text in the arguments.
- Explicit `fail_mode` (`open` / `closed`), required in config and overridable per tool.
- Jev routes: TypeSafe direct, OpenRouter, and Vercel AI Gateway (via `typesafe-sdk`), plus
  Cloudflare Workers AI (REST).
- Approval channels: `CLIApproval`, `WebhookApproval`, `TimeoutDenyApproval`, plus
  `LangGraphInterruptApproval`.
- Append-only JSONL `AuditLog` with verdict, approval, and outcome events.
- Secret and PII redaction for everything sent to Jev or written to the log.
- Adapters: LangGraph, LangChain (callbacks and `create_agent` middleware), OpenAI Agents SDK,
  Google ADK (callbacks and plugin), Semantic Kernel.
- `jev-firewall` CLI: `init`, `check`, `eval`, `audit`.
- Adversarial LangGraph demo, seeded evaluation suites, and benchmark scripts.

Known gaps: accuracy and end-to-end latency against live Jev haven't been measured for this
release (see [docs/benchmarks.md](https://github.com/realahsanshah/jev-action-firewall/blob/master/docs/benchmarks.md)).
