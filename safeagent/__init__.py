"""
SafeAgent — Token safety checks for AI agents.

Usage:
    from safeagent import check_token, is_safe

    result = check_token("0x...", chain="base")
    print(result["safety_score"])  # 0-100

    safe = is_safe("0x...", chain="base", min_score=60)
"""

import urllib.request
import json
from typing import Optional

API_BASE = "https://cryptogenesis.duckdns.org/token"
MCP_URL = "https://cryptogenesis.duckdns.org/mcp"

CHAINS = ["base", "ethereum", "arbitrum", "optimism", "polygon", "bsc"]

# ERC-7913 Oracle addresses
ORACLES = {
    "optimism": "0x3B8A6D696f2104A9aC617bB91e6811f489498047",
    "base": "0x37b9e9B8789181f1AaaD1cD51A5f00A887fa9b8e",
}

FLAGS = {
    "UNVERIFIED": 1 << 0,
    "HONEYPOT": 1 << 1,
    "HIDDEN_MINT": 1 << 2,
    "BLACKLIST": 1 << 3,
    "FEE_MANIPULATION": 1 << 4,
    "TRADING_PAUSE": 1 << 5,
    "PROXY_UPGRADEABLE": 1 << 6,
    "SELF_DESTRUCT": 1 << 7,
    "DELEGATECALL": 1 << 8,
    "OWNERSHIP_NOT_RENOUNCED": 1 << 9,
    "LOW_LIQUIDITY": 1 << 10,
    "LP_NOT_LOCKED": 1 << 11,
    "HIGH_TAX": 1 << 12,
}


def check_token(address: str, chain: str = "base", timeout: int = 10) -> dict:
    """Check if a token is safe. Returns score 0-100, verdict, and risk flags.

    Args:
        address: Token contract address (0x...)
        chain: base, ethereum, arbitrum, optimism, polygon, bsc
        timeout: Request timeout in seconds

    Returns:
        dict with safety_score, verdict, flags, token info
    """
    if chain not in CHAINS:
        raise ValueError(f"Unsupported chain: {chain}. Use: {CHAINS}")

    url = f"{API_BASE}/scan?address={address}&chain={chain}"
    req = urllib.request.Request(url)
    resp = urllib.request.urlopen(req, timeout=timeout)
    return json.loads(resp.read().decode())


def is_safe(address: str, chain: str = "base", min_score: int = 60) -> bool:
    """Quick boolean check: is this token safe enough to trade?

    Args:
        address: Token contract address
        chain: Chain name
        min_score: Minimum acceptable safety score (0-100)

    Returns:
        True if token scores >= min_score
    """
    result = check_token(address, chain)
    return result.get("safety_score", 0) >= min_score


def decode_flags(bitmask: int) -> list:
    """Decode a risk flags bitmask into human-readable flag names."""
    return [name for name, bit in FLAGS.items() if bitmask & bit]


__version__ = "1.0.0"
__all__ = ["check_token", "is_safe", "decode_flags", "FLAGS", "CHAINS", "ORACLES", "MCP_URL"]

# SafeWeb3 — drop-in replacement for Web3
try:
    from safeagent.web3 import SafeWeb3
    __all__.append("SafeWeb3")
except ImportError:
    pass  # web3 not installed — SafeWeb3 not available
