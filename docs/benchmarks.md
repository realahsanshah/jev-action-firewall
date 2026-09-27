# Benchmarks

Everything here is reproducible with the scripts in `benchmarks/`. Only measured numbers are
reported. Anything that needs an API key that wasn't available is marked **not measured**.

## Latency overhead: `benchmarks/overhead.py`

| mode | what it measures | status |
|---|---|---|
| `no_firewall` | the tool call alone | measured |
| `firewall_local` | the full library path with an in-memory, zero-latency Jev: redaction, rule resolution, event-loop hop, audit write | measured |
| `firewall_jev` | end to end with live Jev, network included | **not measured** (needs `TYPESAFE_API_KEY`) |
| `llm_guardrail` | the same three-question check done by Claude Haiku 4.5 returning JSON | **not measured** (needs `ANTHROPIC_API_KEY`) |

Measured 2026-09-27, Windows 11, Python 3.12.10, 2,000 calls, audit log on
(`benchmarks/results/overhead-20260927T165741Z.json`):

| mode | p50 ms | p95 ms | p99 ms |
|---|---|---|---|
| no_firewall | 0.004 | 0.005 | 0.005 |
| firewall_local | **1.02** | **1.50** | 1.91 |

Where the ~1 ms goes (profiled): about 0.2 ms of engine work, about 0.1 ms for the audit
write, and about 0.7 ms for the hop to the engine's dedicated event loop. That loop owns the
Jev HTTP client, so one engine can serve sync tools, async tools, and thread pools without
"attached to a different loop" errors. The hop is slower on Windows than on Linux.

The end-to-end target is under 200 ms at p95 per intercepted action, network included. That
is dominated by the Jev round trip, which has not been measured here yet.

## Accuracy: `benchmarks/run_suites.py`

Seeded suites in `benchmarks/suites/`:

- `destructive.yaml`: 30 destructive actions (shell, SQL, cloud, IAM, payments, file writes). All must be HOLD or DENY.
- `injected.yaml`: 20 actions an agent proposes after reading attacker-controlled content. The goal is the user's real request. All must be HOLD or DENY.
- `benign.yaml`: 40 normal actions that serve the stated goal. Fewer than 10% may be held or denied.

Cases tagged `hard: true` must be caught by the default hard patterns alone. That is enforced
by `tests/test_demo.py::test_hard_marked_cases_are_caught_by_patterns`.

| layers | false negatives | false positives | status |
|---|---|---|---|
| hard patterns only (`--layers hard`) | 31 / 50 | 0 / 40 | measured |
| Jev only (`--layers jev`) | | | **not measured** |
| Jev + hard patterns (default) | | | **not measured** |

The hard-pattern-only row shows what regexes can catch: the unambiguous 19, with no false
positives. The other 31 (dropping a production database without a matching pattern, IAM
escalation, a changed wire amount, exfiltration by email) are exactly the cases that need a
model. Run `python benchmarks/run_suites.py` with `TYPESAFE_API_KEY` set to fill in the rest.
It writes JSON and markdown to `benchmarks/results/`.

`--offline` runs the suites through `FakeJevClient`, a keyword heuristic. It only checks that
the pipeline works. Its numbers say nothing about Jev and are labeled that way in every output.

## Cost

Jev bills input tokens only ($0.042 per million for `jev-1.13`; output is free). One decision
sends the three-field state plus the three questions. The questions are sent every time but
their wording is fixed.

- **Estimate:** a typical request is about 2,700 characters, roughly 680 tokens (chars/4), so
  **about $0.00003 per decision**. That's roughly 35,000 decisions per dollar.
- **Measured:** not yet. The live runs record `usage.input_tokens` per decision, and
  `run_suites.py` reports the mean.

Static `allow`/`deny` rules and `deny` hard-pattern floors skip Jev and cost nothing.
