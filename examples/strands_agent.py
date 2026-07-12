"""Wrap AgentCore Memory with Engram for a Strands agent.

The integration is one construction line: the agent keeps calling the same
memory surface; Engram governs every write and read underneath. Requires
`pip install engram[agentcore]` and a Strands install.

    python examples/strands_agent.py
"""

from engram import GovernedMemory, Policy
from engram.backends.agentcore import AgentCoreBackend

MEMORY_ID = "your-agentcore-memory-id"
TENANT = "acme"

# One line to govern: wrap the AgentCore backend instead of calling it directly.
memory = GovernedMemory(
    backend=AgentCoreBackend(memory_id=MEMORY_ID, region="us-east-1"),
    tenant_id=TENANT,
    policy=Policy.load("policies/policy.yaml"),
)


def remember(text: str, channel: str, actor_id: str) -> None:
    # web/tool/email content arrives as source_channel="web_fetch"/"tool_output"/...
    # and is held by the trust gate until the out-of-band scan clears it.
    memory.write(text, f"tenants/{TENANT}/notes/{actor_id}", channel, actor_id)


def recall(query: str, actor_id: str):
    return memory.retrieve(f"tenants/{TENANT}/notes/{actor_id}", query)


# --- Strands wiring sketch -------------------------------------------------
# from strands import Agent
# def memory_tool(action, **kw):
#     if action == "remember": remember(kw["text"], kw["channel"], kw["actor_id"])
#     if action == "recall":   return [r.content for r in recall(kw["query"], kw["actor_id"])]
# agent = Agent(tools=[memory_tool], ...)
#
# The agent's tool surface is unchanged; provenance, retention, poisoning
# defense, and Article 17 erasure are enforced by Engram, not the agent.

if __name__ == "__main__":
    remember("customer prefers email over phone", "user_turn", "u1")
    print(recall("contact preference", "u1"))
