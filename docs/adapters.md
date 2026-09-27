# Adapters

Every adapter is a thin translation layer: it turns the framework's tool hook into a
`ToolCall(tool_name, tool_args, agent_goal, call_id)` and hands it to the shared `Firewall`:

```python
firewall.check(call)          # veto-style hooks: returns the Verdict or raises ActionBlocked
firewall.guard(call, execute) # wrap-style hooks: check, then run and audit the tool
# async: acheck / aguard
```

DENY raises `ActionBlocked`. HOLD awaits the approval channel, and a rejection also raises
`ActionBlocked` (with `.approval` set). ALLOW runs the tool. No adapter contains policy logic.

Each framework surfaces an exception from its hook differently. The table shows what you
actually catch:

| Framework | Hook | On block by default | What the caller sees |
|---|---|---|---|
| LangGraph | `ToolNode(wrap_tool_call=...)` | `on_block="raise"` | `ActionBlocked` from `graph.invoke`. `on_block="message"` returns an error `ToolMessage` so the model can carry on. |
| LangChain callbacks | `on_tool_start` (sync handler, `raise_error=True`) | raise | `ActionBlocked` from `tool.invoke` / `ainvoke` |
| LangChain `create_agent` | `AgentMiddleware.wrap_tool_call` | `on_block="message"` | error `ToolMessage` |
| OpenAI Agents SDK | `FunctionTool.tool_input_guardrails` | `on_block="raise"` | `AgentsActionBlocked`, a subclass of both `ActionBlocked` and `AgentsException`, so the SDK doesn't wrap it. `on_block="reject"` sends the model a rejection. |
| Google ADK callbacks | `before_tool_callback` | `on_block="raise"` | `ActionBlocked`. `on_block="result"` returns `{"error": ...}` as the tool result. |
| Google ADK plugin | `BasePlugin.before_tool_callback` | `on_block="result"` | the tool result. With `"raise"`, ADK wraps plugin errors in `RuntimeError` and `ActionBlocked` is its `__cause__`. |
| Semantic Kernel | `FUNCTION_INVOCATION` filter | `on_block="raise"` | `KernelInvokeException` with `ActionBlocked` as `__cause__` (SK wraps function errors). `on_block="result"` returns a refusal as the function result. |

Why these choices:

- **LangChain:** LangChain swallows exceptions from *async* callback handlers on the sync
  tool path, so the handler is deliberately synchronous. It runs on both paths.
- **OpenAI Agents SDK:** `RunHooks.on_tool_start` can observe but not veto. Tool input
  guardrails run before the tool body and can block it.
- **Semantic Kernel:** only the function's *declared parameters* are sent as `tool_args`.
  Chat history and settings riding in `KernelArguments` never reach Jev.

## `agent_goal`

Goal-mismatch detection (the prompt-injection signal) needs a one-line statement of what the
user asked for. The defaults use only the user's own words:

| Adapter | default goal |
|---|---|
| LangGraph / `create_agent` | first human message in `state["messages"]` |
| LangChain callbacks | `goal=` argument, else `metadata["agent_goal"]` from the run config |
| OpenAI Agents SDK | first user item in the turn input |
| Google ADK | the user content that started the invocation |
| Semantic Kernel | first user message of a `chat_history` argument, or `goal=` |

Every adapter accepts `goal="..."` or `goal=callable`. Without a goal, the
`matches_stated_goal` question is skipped and the verdict says so
(`no_agent_goal:goal_check_skipped`).

## HOLD in LangGraph without blocking a thread

```python
from jev_firewall.adapters.langgraph import LangGraphInterruptApproval

firewall = Firewall(PolicyEngine.from_yaml("policy.yaml"), LangGraphInterruptApproval())
graph = builder.compile(checkpointer=InMemorySaver())
state = graph.invoke(inputs, config)            # state["__interrupt__"][0].value holds the held call
graph.invoke(Command(resume={"approved": True, "resolver": "alice"}), config)
```

LangGraph re-runs the node on resume. The adapter caches the verdict by tool-call id, so Jev is
called once and one verdict is logged.

## Writing an adapter

1. Find the framework's pre-execution hook, one that can prevent the tool from running.
2. Build a `ToolCall`. Use the framework's tool-call id as `call_id` when there is one, so the
   audit log lines up with the framework's traces.
3. Call `firewall.check`/`acheck` (veto hooks) or `guard`/`aguard` (wrapping hooks).
4. If the framework wraps exceptions, document what the caller sees, and offer a
   "return a refusal to the model" mode.
5. Import the framework only inside `jev_firewall/adapters/<name>.py` and add an optional
   extra in `pyproject.toml`. `tests/test_guard.py::test_core_does_not_import_frameworks`
   enforces that the core package never imports a framework.

No change to the core package is needed. None of the five adapters here needed one.
