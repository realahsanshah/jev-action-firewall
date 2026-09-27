# Jev Action Firewall — PRD

Sep 27, 2026 · @Ahsan Shah

## Problem & Goals

**Problem.** Agent frameworks execute tool calls (file writes, terminal commands, emails, payments, DB mutations) with no verification layer between "the LLM decided to do X" and "X happened." A hallucinated or manipulated decision causes real, sometimes irreversible, harm. Existing mitigations are either a second LLM call (expensive, slow, still can hallucinate) or static regex/allowlist rules (cheap, but can't reason about context).

**Goal.** Ship a runtime action firewall that sits between any popular agent framework and tool execution, using Jev (TypeSafe's System One decision model) to score every proposed action on severity and irreversibility before it runs — with near-zero added latency and cost, and a single core engine reused across frameworks rather than a reimplementation per framework.

## Users & Use Cases

**Primary user:** an AI/platform engineer wiring an agent (LangGraph, LangChain, OpenAI Agents SDK, Semantic Kernel / Microsoft Agent Framework, or Google ADK) who needs a guardrail layer that's fast and cheap enough to run on every tool call, not just the risky-looking ones.

**Core use cases**

- Blocking or holding destructive terminal commands (`rm -rf`, `DROP TABLE`)
- Gating outbound actions with real-world side effects (send email, post message, place order)
- Gating financial/payment actions (refund, transfer, charge)
- Flagging DB writes/deletes for approval above a configurable blast-radius threshold
- Auditing every agent decision for post-hoc review, even ones that were allowed

## Scope

**In scope — v1**

- Core policy engine (framework-agnostic): risk thresholds, verdicts, approval channel interface, audit log
- Jev client wrapper (direct API + at least one gateway route)
- LangGraph adapter
- One adversarial demo (agent attempts a destructive action; firewall catches it)

**In scope — v1.1**

- Adapters: LangChain, OpenAI Agents SDK, Microsoft Agent Framework / Semantic Kernel, Google ADK
- Latency and cost benchmark suite vs. an LLM-based guardrail

**Out of scope**

- Training or fine-tuning a model
- Non-agentic guardrail use cases (e.g. standalone content moderation with no tool-call context)
- A hosted dashboard/UI (candidate for v2)

## Success Metrics

| Metric                                                     | Target                                                                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Added latency per intercepted action (p95)                 | < 200 ms                                                                                                |
| Cost per decision                                          | < $0.0001                                                                                               |
| False negatives on seeded destructive actions (demo suite) | 0                                                                                                       |
| False positive rate on benign actions (demo suite)         | < 10%                                                                                                   |
| Framework adapters shipped                                 | ≥ 4 (LangGraph, LangChain, OpenAI Agents SDK, Google ADK, + Semantic Kernel/Agent Framework as stretch) |
| Public artifacts                                           | GitHub repo, README, benchmark writeup, adversarial demo recording                                      |

## Functional Requirements

1. Intercept every proposed tool call before execution, across all supported frameworks, via a thin per-framework adapter that calls into one shared core.
2. Evaluate each proposed action against Jev using two typed questions: a Choice (severity tier) and a Noul (is this irreversible).
3. Support per-tool and per-pattern (glob/regex on tool name) risk thresholds, configurable by the integrator.
4. Return one of three verdicts: **allow**, **hold-for-approval**, **deny**.
5. Provide a pluggable approval channel (CLI prompt, Slack/webhook, auto-deny-on-timeout) for held actions.
6. Log every decision (action, Jev response, verdict, latency, outcome) to a structured, queryable audit trail.
7. Support both fail-open and fail-closed behavior on Jev API failure/timeout, configurable per deployment.
8. Abstract the Jev access route (direct API, OpenRouter, Vercel AI Gateway, Cloudflare Workers AI) behind one client interface.

## Non-Functional Requirements

- **Latency:** the firewall's own overhead (excluding Jev network time) should be negligible; end-to-end added latency per action target < 200 ms p95.
- **Cost:** input-token-only billing means cost scales with state size, not question count — the core engine should keep the state payload sent to Jev minimal (only what's needed to judge the action).
- **Reliability:** timeouts and retries on the Jev client; explicit, documented fail-open vs. fail-closed behavior rather than an implicit default.
- **Security:** no secrets, credentials, or unrelated conversation history are sent in the Jev state payload — only the action being judged and the minimal context needed to judge it.
- **Extensibility:** adding a new framework adapter should require no changes to the core engine, only a new thin adapter implementing the same interface.
