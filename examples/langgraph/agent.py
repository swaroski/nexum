"""LangGraph agent whose tools are gated by a Nexum gateway.

The model decides *what it wants to do*; Nexum decides *whether it may*.
Each tool asks the gateway before acting, so a prompt-injected or confused
model cannot exceed the authority in its delegation grant.

    pip install langgraph langchain-core cryptography
    export NEXUM_GATEWAY=http://127.0.0.1:8088
    export NEXUM_GRANTS=root.jwt            # comma-separated, root first
    export NEXUM_KEY=procurement.key.json
    python agent.py

Plug `tools` into any LangGraph graph, e.g. `create_react_agent(model, tools)`.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from langchain_core.tools import tool  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402

from nexum_client import NexumClient  # noqa: E402

nexum = NexumClient(
    os.environ.get("NEXUM_GATEWAY", "http://127.0.0.1:8080"),
    os.environ["NEXUM_GRANTS"].split(","),
    os.environ["NEXUM_KEY"],
)


class NotAuthorized(Exception):
    pass


def require(action: str, resource: str, value: int | None = None) -> None:
    d = nexum.authorize(action, resource, value)
    if d.outcome == "REQUIRE_APPROVAL":
        raise NotAuthorized(f"needs human approval {d.approval_id}: {d.message}")
    if not d.allowed:
        raise NotAuthorized(f"{d.code}: {d.message}")


@tool
def read_inventory(sku: str) -> str:
    """Read stock level for a supplier SKU."""
    require("inventory.read", f"supplier://abc/sku/{sku}")
    return f"SKU {sku}: 42 units"  # call the real supplier API here


@tool
def create_quote(amount_usd: int) -> str:
    """Request a purchase quote for the given amount."""
    require("quote.create", "supplier://abc/quote/new", amount_usd)
    return f"quote created for ${amount_usd}"


tools = [read_inventory, create_quote]
tool_node = ToolNode(tools, handle_tool_errors=True)

if __name__ == "__main__":
    # Exercise the tools directly, without a model.
    for name, args in [("read_inventory", {"sku": "123"}), ("create_quote", {"amount_usd": 250_000})]:
        try:
            print(name, "->", next(t for t in tools if t.name == name).invoke(args))
        except NotAuthorized as e:
            print(name, "-> blocked:", e)
