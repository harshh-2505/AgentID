# Framework examples

Short, **illustrative** snippets showing one tool wrapped with the AgentID adapter in
popular agent frameworks. They are not run by the test suite and need the framework
installed; the adapter itself is tested in `test/adapters.test.js` and
`sdk-python/tests/test_agentid.py`.

| File | Framework | Adapter |
| --- | --- | --- |
| `langgraph_agent.py` | LangGraph (Python) | `@guard` under `@tool` |
| `openai_agents.py` | OpenAI Agents SDK (Python) | `@guard`, denial returned to the model |
| `crewai_tool.py` | CrewAI (Python) | `@guard` with a co-sign wait |
| `claude-agent-sdk.ts` | Claude Agent SDK (TypeScript) | `withAgentID` inside an SDK MCP tool |

The pattern is the same everywhere: before the tool body runs, the adapter signs an
Intent (action, resource, params, reason), sends it to the authority, and then

- **allow**: runs the tool and hands it the signed receipt (`ctx.receipt` in JS,
  `current_receipt()` in Python) to forward in the `agentid-receipt` header;
- **step_up**: waits for the principal's co-sign, up to `timeoutMs` / `timeout`;
- **deny**: throws `AgentIDDenied` (or `AgentIDTimeout`) without running the tool.

Each snippet loads `agent.json`, the output of `AgentRuntime.export()` (JS) or
`Agent.export()` (Python) for an agent whose passport and mandate are registered;
`examples/autonomous-agent.js` shows how to create one. The authority checks the
agent's key, runtime attestation, mandate and budget on every call, so prompts or
tool arguments cannot widen what the agent is allowed to do.
