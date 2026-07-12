"""Use Memwarden as the governed memory behind a LangGraph agent.

Memwarden sits between the graph's memory node and the store. Reads return only
post-gate records (quarantine → TTL → integrity → trust), so poisoned or
unverified content never enters the graph state. Requires a LangGraph install
and, for the backend shown, `pip install memwarden[agentcore]`.
"""

from memwarden import GovernedMemory, Policy
from memwarden.backends.inmemory import InMemoryBackend  # swap for AgentCoreBackend/RedisBackend

memory = GovernedMemory(backend=InMemoryBackend(), tenant_id="acme",
                        policy=Policy.load("policies/policy.yaml"))
NS = "tenants/acme/threads/{thread_id}"


def write_memory(state: dict) -> dict:
    """Graph node: persist the latest turn, tagged with its provenance channel."""
    memory.write(state["content"], NS.format(thread_id=state["thread_id"]),
                 source_channel=state.get("channel", "user_turn"),
                 actor_id=state["actor_id"])
    return state


def read_memory(state: dict) -> dict:
    """Graph node: only admitted (governed) records reach the model's context."""
    recs = memory.retrieve(NS.format(thread_id=state["thread_id"]), state["query"])
    state["context"] = [r.content for r in recs]
    return state


# --- LangGraph wiring sketch ----------------------------------------------
# from langgraph.graph import StateGraph
# g = StateGraph(dict)
# g.add_node("write_memory", write_memory)
# g.add_node("read_memory", read_memory)
# g.add_edge("read_memory", "call_model")   # model sees only governed context
# app = g.compile()

if __name__ == "__main__":
    write_memory({"thread_id": "t1", "actor_id": "u1",
                  "content": "user is based in the EU (GDPR applies)", "channel": "user_turn"})
    print(read_memory({"thread_id": "t1", "actor_id": "u1", "query": "user location"}))
