#!/usr/bin/env python3
"""Minimal SSE MCP server on port 4024 — for Glama inspector."""
import json
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "SafeAgent",
    instructions="Token safety oracle. FREE during beta. ERC-7913.",
    host="0.0.0.0",
    port=4024,
)

SCANNER = "http://localhost:4444"

@mcp.tool()
def check_token_safety(address: str, chain: str = "base") -> str:
    """Check if a token is safe. Honeypot detection, 17 scam patterns, 6 EVM chains. Score 0-100."""
    try:
        r = requests.get(f"{SCANNER}/scan", params={"address": address, "chain": chain}, timeout=10)
        if r.ok:
            d = r.json()
            return f"Score: {d.get('safety_score','?')}/100 — {d.get('verdict','?')}"
        return f"Error: {r.status_code}"
    except Exception as e:
        return str(e)

@mcp.tool()
def ping() -> str:
    """Health check."""
    return "SafeAgent OK"

if __name__ == "__main__":
    mcp.run(transport="sse")
