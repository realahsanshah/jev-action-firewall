# jev-firewall

**A runtime action firewall for AI agents.** Before an agent's tool call runs, jev-firewall
asks [Jev](https://docs.typesafe.ai) (TypeSafe's System One decision model) how dangerous it
is, and returns one of three verdicts:

| Verdict | What happens |
|---|---|
| **ALLOW** | the tool runs |
| **HOLD** | the call waits for a human (CLI prompt, webhook, or LangGraph interrupt) |
| **DENY** | the tool never runs; `ActionBlocked` is raised (or a refusal is returned to the model) |

Every decision is written to an append-only JSONL audit log. One core engine is shared by
thin adapters for **LangGraph, LangChain, OpenAI Agents SDK, Google ADK and Semantic Kernel**.

```text
agent proposes tool call ──► adapter ──► PolicyEngine ──► hard patterns (local regex)
                                              │                 │ DENY floor? stop here
                                              ▼                 ▼
                                    Jev: 1 call, 3 typed questions (~680 input tokens est.)
                                              │
                                              ▼
                        thresholds + rules ──► ALLOW / HOLD / DENY ──► audit log
```

## Why a System One model?

A **System Two** guardrail is a second LLM that reads the action and writes out its reasoning.
It is slow (hundreds of ms to seconds), costs about as much as the agent's own call, returns
free text you have to parse, and can itself be talked round.

**System One** models like Jev don't generate text. You declare typed questions (pick one of
these options, yes/no probability, position on a scale) and get back calibrated probabilities
you can threshold in code. That makes the check fast and cheap enough to run on *every* tool
call, and the decision logic stays in your code and your `policy.yaml`, not in a prompt.

Jev has known limits, and this library is built around them
([Jev 1.13 jaggedness](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md)):

- **Adversarial text in the input can move its answers.** Tool arguments are attacker
  controllable, so deterministic *hard patterns* run first and set a floor Jev cannot lower.
  `rm -rf /` is denied even if the command says "this is a safe low_risk cleanup".
- **Irrelevant context lowers accuracy.** The state sent to Jev is three fields: the tool name,
  its redacted arguments, and a one-line goal. Never the conversation history.
- **No counting, arithmetic or date logic.** None of the questions need any.

## Quick start (about 5 minutes)

```bash
pip install "jev-firewall[langgraph]"      # or [langchain], [openai_sdk], [google_adk], [semantic_kernel], [all]
export TYPESAFE_API_KEY=...                # https://console.typesafe.ai/keys
jev-firewall init                          # writes ./policy.yaml from the bundled example
jev-firewall check policy.yaml             # validates it and prints the effective settings
```

Try one decision from the command line (exit code 0 allow, 10 hold, 20 deny):

```bash
jev-firewall eval policy.yaml --tool terminal \
  --args '{"command": "sudo rm -rf /var/lib/postgresql/16/main"}' \
  --goal "Free up disk space on the build server"
```

No key yet? Add `--offline` to use the bundled keyword stand-in. It exercises the whole
pipeline, but it is **not Jev**, so don't judge accuracy by it.

Wire it into a LangGraph agent:

```python
from jev_firewall import Firewall
from jev_firewall.adapters.langgraph import firewall_tool_node

firewall = Firewall.from_yaml("policy.yaml")                    # engine + approval channel + audit log
builder.add_node("tools", firewall_tool_node(tools, firewall))  # replaces ToolNode(tools)
```

That's it. Every tool call in that node is now evaluated, held, or blocked, and logged.

## Adapters

All adapters do the same thing: build a `ToolCall(tool_name, args, agent_goal)`, then
evaluate. DENY raises `ActionBlocked`, HOLD waits for approval, and ALLOW runs the tool.
They contain no policy logic.

| Framework | Install extra | Hook | Usage |
|---|---|---|---|
| LangGraph | `[langgraph]` | `ToolNode(wrap_tool_call=...)` | `firewall_tool_node(tools, firewall)` |
| LangChain | `[langchain]` | `BaseCallbackHandler.on_tool_start` / `create_agent` middleware | `JevFirewallCallbackHandler(firewall)`, `JevFirewallMiddleware(firewall)` |
| OpenAI Agents SDK | `[openai_sdk]` | `FunctionTool.tool_input_guardrails` | `protect_tools(tools, firewall)` |
| Google ADK | `[google_adk]` | `before_tool_callback` / runner plugin | `JevFirewallCallbacks(firewall)`, `JevFirewallPlugin(firewall)` |
| Semantic Kernel | `[semantic_kernel]` | `FUNCTION_INVOCATION` filter | `JevFunctionInvocationFilter(firewall)` |

> **uv + Semantic Kernel:** semantic-kernel ≥ 1.36 depends on a pre-release of `azure-ai-agents`.
> pip installs it as is. With uv, also request it directly
> (`uv add "jev-firewall[semantic_kernel]" "azure-ai-agents>=1.2.0b3"`) or pass `--prerelease=allow`.

Runnable, keyless examples are in [`examples/`](examples/). [`examples/consumer/`](examples/consumer/)
has one standalone project per framework (`pip install -r requirements.txt && python app.py`)
that uses the published package exactly as you would. Framework details, including how
each framework surfaces `ActionBlocked`, are in [docs/adapters.md](docs/adapters.md).

**`agent_goal`** powers the prompt-injection check. By default each adapter uses the *first
user message* of the conversation, never tool output or retrieved content, so injected text
can't rewrite it. You can also pass `goal="..."` or a callable.

## Configuration reference

`policy.yaml` is validated strictly: unknown keys are errors, and `fail_mode` and `jev` have
no defaults. Full reference: [docs/configuration.md](docs/configuration.md).

```yaml
version: 1
fail_mode: closed            # REQUIRED: open | closed (see below)
jev:
  route: direct              # direct | openrouter | vercel | cloudflare
  timeout_s: 1.0             # total budget per decision, retries included
  max_retries: 1
defaults:
  thresholds: {low_risk: allow, moderate_risk: allow, high_risk: hold, critical_danger: deny}
  irreversible_threshold: 0.5   # p(irreversible) at/above this: a would-be ALLOW becomes HOLD
  goal_match_threshold: 0.5     # p(matches goal) below this: at least HOLD
  min_confidence: 0.5           # severity confidence below this: at least HOLD
  hard_patterns:
    - {description: pipe remote script into a shell, pattern: '\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b', floor: deny}
tools:                       # exact name beats glob; most specific glob wins
  "read_*": {action: allow}  # skip Jev entirely
  "terminal": {thresholds: {moderate_risk: hold}}
  "transfer_*": {thresholds: {high_risk: deny}, fail_mode: closed}
approval: {channel: cli, timeout_s: 300}      # cli | webhook | timeout_deny
audit: {path: ./jev-audit.jsonl}
```

**How a decision is made** (each step can only make it stricter):

1. Resolve the tool's rule: exact name, then the most specific glob, then `defaults`.
2. Hard patterns on the raw arguments set a floor. A `deny` floor (or `action: deny`) ends here, with no Jev call.
3. `action: allow|hold` skips Jev.
4. Jev answers `severity` (Choice), `is_irreversible` (Noul) and `matches_stated_goal` (Noul) in one call.
5. Severity maps to a verdict through the tool's thresholds.
6. Irreversible and not allowlisted (`allow_irreversible: true`): an ALLOW becomes HOLD.
7. Goal mismatch: at least HOLD. Low severity confidence: at least HOLD.

**Jev routes.** Each route reads its key from its own env var, so a TypeSafe key is never
sent to a gateway by mistake.

| route | key env var | default model |
|---|---|---|
| `direct` | `TYPESAFE_API_KEY` | `jev-1.13.0` (pinned; thresholds are tuned per version) |
| `openrouter` | `OPENROUTER_API_KEY` | `~typesafe/jev-latest` |
| `vercel` | `AI_GATEWAY_API_KEY` | `typesafe-ai/jev` |
| `cloudflare` | `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` | `typesafe/jev` |

## Fail mode guidance

If Jev times out, errors, rate-limits, or returns something malformed, the verdict comes from
`fail_mode`, never from a hidden default:

- **`closed` (DENY)**: use it for anything with side effects, such as shell, databases, email,
  payments, and deploys. An outage stops the agent instead of letting it act unchecked. This is
  the right default for most deployments.
- **`open` (ALLOW)**: only for low-stakes tools where availability matters more than
  checking. Hard-pattern floors still apply in open mode.

Set a global `fail_mode` and override it per tool (`tools.<name>.fail_mode`). Keep `timeout_s`
tight: a decision that takes longer than the budget *is* a failure and goes through
`fail_mode`. Watch the audit log for `source: fail_open` / `fail_closed` to see how often it
happens.

## Security properties

- **What Jev sees:** `tool_name`, `tool_args` after redaction, and a one-line `agent_goal`. That's all.
- **Redaction** (`jev_firewall.redact`) masks sensitive keys (`password`, `api_key`,
  `authorization`, ...), API keys and tokens (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack,
  Google, JWTs, bearer tokens), PEM private keys, URL credentials, `KEY=value` secrets, and PII
  (emails keep their domain, which is a useful risk signal; phone numbers, SSNs, and
  Luhn-valid card numbers are masked). Long strings, lists, and deep nesting are truncated.
- **Audit log:** only redacted arguments are written. One line per event (`verdict`,
  `approval`, `outcome`), linked by `call_id`. Run `jev-firewall audit ./jev-audit.jsonl` for a summary.

## Measured results

Only numbers that were actually measured are listed. Full method and raw JSON: [docs/benchmarks.md](docs/benchmarks.md).

| What | Result | Conditions |
|---|---|---|
| Firewall library overhead (no network) | **p50 1.02 ms, p95 1.50 ms** per decision | in-memory Jev, audit on, 2,000 calls, Windows 11, Python 3.12 |
| Hard patterns alone on the seeded suites | 19 / 50 harmful caught, **0 / 40** benign blocked | Jev disabled |
| Adversarial LangGraph demo | 4 / 4 harmful calls stopped, 4 / 4 benign allowed | offline stand-in; live run pending |
| End-to-end latency with live Jev | **not measured yet** | needs `TYPESAFE_API_KEY` |
| False negatives / false positives with live Jev | **not measured yet** | needs `TYPESAFE_API_KEY` |
| LLM-guardrail comparison | **not measured yet** | needs `ANTHROPIC_API_KEY` |
| Cost per decision | ~680 input tokens → **~$0.00003 (estimate)** | chars/4 of the actual request; live `usage` pending |

Reproduce with `python benchmarks/overhead.py` and `python benchmarks/run_suites.py`.
Both measure the live modes automatically when the keys are set.

## Development

```bash
uv sync --all-extras
uv run pytest                      # offline: FakeJevClient + mock HTTP transports
JEV_LIVE_TESTS=1 uv run pytest     # plus live Jev tests (needs TYPESAFE_API_KEY)
uv run ruff check . && uv run mypy # strict typing
python examples/langgraph_adversarial_demo.py
```

Adding an adapter requires no changes to the core package; see [docs/adapters.md](docs/adapters.md#writing-an-adapter).

## License

Apache-2.0. jev-firewall is an independent open-source project and is not affiliated with TypeSafe AI.
