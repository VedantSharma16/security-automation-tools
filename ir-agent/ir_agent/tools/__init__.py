"""Individual investigation tools the agent can call.

Each tool is a plain, deterministic Python function with no LLM dependency —
the agent (or a human) decides when to call them; they never call each other
or the LLM themselves. This keeps every tool independently unit-testable and
keeps the "intelligence" (deciding what to call, when, and how to interpret
results) confined to ir_agent.agent.
"""
