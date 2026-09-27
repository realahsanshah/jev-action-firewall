# Configuration reference

`policy.yaml` is loaded by `Policy.from_yaml()` / `Firewall.from_yaml()` and validated
strictly: unknown keys, missing required keys, out-of-range numbers, and invalid regexes are
all `PolicyConfigError` at load time. Run `jev-firewall check policy.yaml` to validate and print
the effective settings. `jev-firewall init` writes the annotated example.

## Top level

| key | required | type | notes |
|---|---|---|---|
| `version` | yes | `1` | schema version |
| `fail_mode` | **yes** | `open` \| `closed` | verdict when Jev is unavailable. No default, on purpose. |
| `jev` | **yes** | mapping | how to reach Jev |
| `defaults` | yes | mapping | thresholds and floors every tool inherits |
| `tools` | no | mapping name/glob → rule | per-tool overrides |
| `approval` | no | mapping | how HOLDs are resolved. Absent means held actions are denied. |
| `audit` | no | mapping | JSONL audit log. Absent means no log (the engine still works). |
| `redaction` | no | mapping | limits for what is sent to Jev |

## `jev`

| key | required | default | notes |
|---|---|---|---|
| `route` | yes | | `direct`, `openrouter`, `vercel`, `cloudflare` |
| `timeout_s` | yes | | total budget per decision **including retries**. Also enforced as a hard `asyncio.timeout`. |
| `max_retries` | yes | | 0–5. Retries 408/429/5xx and connection errors with short backoff inside the budget. |
| `model` | no | per route | `jev-1.13.0` (direct), `~typesafe/jev-latest` (OpenRouter), `typesafe-ai/jev` (Vercel), `typesafe/jev` (Cloudflare) |
| `api_key_env` | no | per route | env var holding the key: `TYPESAFE_API_KEY`, `OPENROUTER_API_KEY`, `AI_GATEWAY_API_KEY`, `CLOUDFLARE_API_TOKEN` |
| `base_url` | no | per route | override the endpoint |
| `account_id_env` | no | `CLOUDFLARE_ACCOUNT_ID` | Cloudflare only |

`direct`, `openrouter`, and `vercel` go through the official `typesafe-sdk`, pointed at the
gateway's `base_url` as TypeSafe documents. Cloudflare Workers AI uses a different URL and
request envelope, so it has its own small REST client with the same question schema.

Pin `model` to a version (the direct route does this by default). Aliases such as `jev-latest`
move when TypeSafe ships a release, and your thresholds were tuned against one model. Every
verdict records the model that answered in `assessment.model`.

## `defaults`

| key | type | meaning |
|---|---|---|
| `thresholds` | map of all 4 tiers → `allow`/`hold`/`deny` | severity tier to verdict. All four tiers are required. |
| `irreversible_threshold` | 0–1 | `is_irreversible` probability at or above this turns an ALLOW into HOLD (unless the tool sets `allow_irreversible: true`) |
| `goal_match_threshold` | 0–1 | `matches_stated_goal` probability **below** this forces at least HOLD |
| `min_confidence` | 0–1 | severity Choice confidence below this forces at least HOLD |
| `hard_patterns` | list | regex floors applied to every tool (see below) |

Severity tiers, and the criteria Jev is given for each:

- `low_risk`: read-only or informational, or a trivial change in a temp location
- `moderate_risk`: a small, scoped change that is easy to undo (one project file, a draft, a git-revertable edit)
- `high_risk`: changes important data or systems, or has effects outside the workspace (deletes, DB writes, messages to others, publishing, deploying, money, permissions)
- `critical_danger`: severe or widespread damage (mass data loss, disabling security, exposing secrets, sending private data out, running downloaded code, large sums of money)

Noul answers (`is_irreversible`, `matches_stated_goal`) have no confidence value in Jev's API,
so `min_confidence` applies to the severity Choice only.

## `tools`

Keys are exact tool names or `fnmatch` globs (`read_*`, `db_?_write`, `[ab]*`). An exact name
beats any glob, and among globs the one with the most literal characters wins. Ties go to
the first one declared. A matching rule is merged over `defaults`; it does not stack with
other matching globs.

| key | default | meaning |
|---|---|---|
| `action` | `evaluate` | `evaluate` asks Jev; `allow` / `hold` / `deny` decide statically and skip Jev |
| `thresholds` | `{}` | partial override of `defaults.thresholds` |
| `fail_mode` | top-level | per-tool override |
| `allow_irreversible` | `false` | allow irreversible actions to ALLOW without a human |
| `irreversible_threshold`, `goal_match_threshold`, `min_confidence` | defaults | per-tool override |
| `hard_patterns` | `[]` | added to `defaults.hard_patterns` for this tool |

Hard patterns still apply to `action: allow` tools. A `read_file` call whose path is
`~/.ssh/id_rsa` still gets the configured floor.

## `hard_patterns`

```yaml
- description: pipe remote script into a shell     # shown in reasons and the audit log
  pattern: '\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b'
  floor: deny                                      # hold | deny
  ignore_case: true                                # default
```

The pattern is searched in the tool name plus every string value of the **raw** arguments
(before redaction), all joined with newlines. This happens locally and is never sent anywhere.
A `deny` floor ends evaluation with no Jev call. A `hold` floor still asks Jev, because Jev
might escalate to DENY.

Patterns are a backstop for the few catastrophic, unambiguous cases. Keep them narrow: a
broad pattern turns into false positives, and Jev handles the nuanced cases. The bundled
set is tested in `tests/test_policy.py::test_example_policy_hard_patterns`, including cases
it must *not* match (`rm -rf ./dist`, `git push origin main`).

## `approval`

| key | notes |
|---|---|
| `channel` | `cli` (prompt on stderr/stdin), `webhook`, `timeout_deny` (reject every HOLD; for unattended agents) |
| `timeout_s` | no answer in time rejects the action. Required for `webhook`. |
| `webhook_url` | required for `webhook`. See `jev_firewall.approval.webhook` for the protocol. |

You can also pass any object with `async def request(req) -> ApprovalResult` to
`Firewall(engine, approval)`. `LangGraphInterruptApproval` pauses the graph with `interrupt()`
instead of blocking.

## `audit`

| key | default | notes |
|---|---|---|
| `path` | required | append-only JSONL |
| `fsync` | `false` | `true` makes each write durable before the tool runs, at some latency cost |

Events: `verdict` (always), `approval` (HOLDs), and `outcome` (`executed`, `blocked`, `error`),
linked by `call_id`. That's the framework's tool-call id when it has one.

## `redaction`

| key | default | notes |
|---|---|---|
| `max_string_chars` | 500 | longer strings are truncated before being sent to Jev |
| `max_items` | 50 | per list or mapping |
| `max_depth` | 6 | nesting limit |
| `max_goal_chars` | 200 | `agent_goal` is also collapsed to a single line |
| `redact_pii` | `true` | emails (domain kept), phone numbers, SSNs, Luhn-valid card numbers |
| `extra_key_patterns` | `[]` | extra regexes for argument keys whose values are always masked |
