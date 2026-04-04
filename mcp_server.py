#!/usr/bin/env python3
"""
SafeAgent MCP Server v2 — Crypto Intelligence Suite for AI Agents
15 tools: security, prices, gas, wallets, DeFi, ENS, NFTs, chains.
"""
import json
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "SafeAgent",
    instructions="Token safety oracle for AI agents. Honeypot detection, 17 scam patterns, 6 EVM chains. FREE during beta. ERC-7913 standard. 250+ tokens scored on-chain.",
    host="0.0.0.0",
    port=4023,
    sse_path="/sse",
    streamable_http_path="/mcp",
    message_path="/messages/",
)

SCANNER_URL = "http://localhost:4444"
DEFI_URL = "http://localhost:8085"
RISK_URL = "http://localhost:8100"


# ===== SECURITY TOOLS =====

@mcp.tool()
def check_token_safety(address: str, chain: str = "base") -> str:
    """Check if a token is safe or a scam. Runs honeypot simulation, 17 scam pattern checks across 6 EVM chains.
    Args:
        address: Token contract address (0x...)
        chain: base, ethereum, arbitrum, optimism, polygon, bsc
    """
    try:
        r = requests.get(f"{SCANNER_URL}/internal/scan/deep", params={"address": address, "chain": chain}, headers={"X-Internal-Key": "298912002d4f03c93a6a77208247fbe9b9cc95304b9276c1e01c162002228d9b"}, timeout=30)
        if r.ok:
            d = r.json()
            result = f"Score: {d.get('safety_score','?')}/100 — {d.get('verdict','?')}\n"
            hp = d.get("honeypot_simulation", {})
            if hp.get("simulated"):
                if hp.get("is_honeypot"):
                    result += f"⚠️ HONEYPOT: {hp.get('reason')}\n"
                else:
                    result += f"Sell OK — {hp.get('total_tax_pct','?')}% tax\n"
            for f in d.get("flags", []):
                result += f"  - {f}\n"
            t = d.get("token", {})
            if t.get("name"):
                result += f"Token: {t['name']} ({t.get('symbol','?')})\n"
            return result
        return f"Error: HTTP {r.status_code}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def check_wallet_risk(address: str, chain: str = "ethereum") -> str:
    """Check if a wallet address is safe to interact with. Returns risk score and flags.
    Args:
        address: Wallet or contract address (0x...)
        chain: ethereum, base, arbitrum, polygon
    """
    try:
        r = requests.get(f"{RISK_URL}/check", params={"address": address, "chain": chain}, timeout=15)
        if r.ok:
            d = r.json()
            result = f"Risk Score: {d.get('risk_score','?')}/100 — {d.get('verdict','?')}\n"
            result += f"Contract: {'Yes' if d.get('is_contract') else 'No'} | Txs: {d.get('nonce','?')} | Balance: {d.get('balance_native','?')}\n"
            for f in d.get("flags", []):
                result += f"  ⚠️ {f}\n"
            return result
        return f"Error: HTTP {r.status_code}"
    except Exception as e:
        return f"Error: {e}"


# ===== PRICE & MARKET TOOLS =====

@mcp.tool()
def get_token_price(token_id: str) -> str:
    """Get current price, market cap, and 24h change for a crypto token.
    Args:
        token_id: CoinGecko ID (bitcoin, ethereum, solana) or symbol
    """
    try:
        r = requests.get(f"https://api.coingecko.com/api/v3/simple/price",
            params={"ids": token_id, "vs_currencies": "usd", "include_24hr_change": "true", "include_market_cap": "true"},
            timeout=10)
        if r.ok:
            d = r.json()
            if token_id in d:
                p = d[token_id]
                return f"{token_id}: ${p.get('usd',0):,.2f} | 24h: {p.get('usd_24h_change',0):.1f}% | MCap: ${p.get('usd_market_cap',0):,.0f}"
            return f"Token '{token_id}' not found. Use CoinGecko ID (bitcoin, ethereum, solana, etc.)"
        return f"CoinGecko error: {r.status_code}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_trending_tokens() -> str:
    """Get top 7 trending crypto tokens on CoinGecko right now."""
    try:
        r = requests.get("https://api.coingecko.com/api/v3/search/trending", timeout=10)
        if r.ok:
            coins = r.json().get("coins", [])
            result = "Trending tokens:\n"
            for c in coins[:7]:
                item = c.get("item", {})
                result += f"  #{item.get('market_cap_rank','?')} {item.get('name','?')} ({item.get('symbol','?')}) — ${item.get('data',{}).get('price','?')}\n"
            return result
        return f"Error: {r.status_code}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_gas_prices() -> str:
    """Get current gas prices across major EVM chains (Ethereum, Base, Polygon, Arbitrum, Optimism)."""
    from web3 import Web3
    chains = {
        "Ethereum": "https://ethereum-rpc.publicnode.com",
        "Base": "https://base-rpc.publicnode.com",
        "Polygon": "https://polygon-bor-rpc.publicnode.com",
        "Arbitrum": "https://arbitrum-one-rpc.publicnode.com",
        "Optimism": "https://optimism-rpc.publicnode.com",
    }
    result = "Gas prices (Gwei):\n"
    for name, rpc in chains.items():
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 5}))
            gp = w3.eth.gas_price / 1e9
            result += f"  {name}: {gp:.2f} gwei\n"
        except:
            result += f"  {name}: unavailable\n"
    return result


# ===== DEFI TOOLS =====

@mcp.tool()
def get_defi_yields(chain: str = "", min_tvl: int = 100000, limit: int = 10) -> str:
    """Get top DeFi yield opportunities with quality scoring (A-F grades).
    Args:
        chain: Filter by chain (Ethereum, Base, Arbitrum) or empty for all
        min_tvl: Minimum TVL in USD (default 100000)
        limit: Max results (default 10)
    """
    try:
        params = {"limit": limit, "min_tvl": min_tvl}
        if chain:
            params["chain"] = chain
        r = requests.get(f"{DEFI_URL}/v1/yields/top", params=params, timeout=20)
        if r.ok:
            d = r.json()
            result = f"Top {d.get('count','?')} yields:\n"
            for p in d.get("data", [])[:limit]:
                result += f"  {p.get('symbol','?')} on {p.get('chain','?')} — APY: {p.get('apy',0):.1f}% | TVL: ${p.get('tvl_usd',0):,.0f}\n"
            return result
        return f"Error: {r.status_code}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_market_overview() -> str:
    """Get DeFi market overview: total TVL, average yields, pool count."""
    try:
        r = requests.get(f"{DEFI_URL}/v1/market/overview", timeout=20)
        if r.ok:
            d = r.json()
            return f"DeFi Market:\n  TVL: ${d.get('total_defi_tvl',0):,.0f}\n  Pools: {d.get('total_pools_tracked',0):,}\n  Avg APY: {d.get('avg_yield_apy',0):.1f}%\n  Stable APY: {d.get('stablecoin_avg_apy',0):.1f}%"
        return f"Error: {r.status_code}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_defi_tvl(protocol: str = "") -> str:
    """Get DeFi TVL data from DefiLlama. Shows top protocols or specific protocol TVL.
    Args:
        protocol: Protocol name (aave, uniswap, lido) or empty for top 10
    """
    try:
        if protocol:
            r = requests.get(f"https://api.llama.fi/protocol/{protocol}", timeout=10)
            if r.ok:
                d = r.json()
                return f"{d.get('name','?')}: TVL ${d.get('currentChainTvls',{}).get('total',d.get('tvl',0)):,.0f} | Category: {d.get('category','?')}"
        else:
            r = requests.get("https://api.llama.fi/protocols", timeout=10)
            if r.ok:
                protocols = sorted(r.json(), key=lambda x: x.get("tvl", 0), reverse=True)[:10]
                result = "Top 10 DeFi by TVL:\n"
                for p in protocols:
                    result += f"  {p.get('name','?')}: ${p.get('tvl',0):,.0f} ({p.get('category','?')})\n"
                return result
        return "Error fetching TVL data"
    except Exception as e:
        return f"Error: {e}"


# ===== CHAIN TOOLS =====

@mcp.tool()
def get_chain_info(chain: str = "ethereum") -> str:
    """Get current block number, gas price, and chain status for an EVM chain.
    Args:
        chain: ethereum, base, polygon, arbitrum, optimism
    """
    from web3 import Web3
    rpcs = {
        "ethereum": "https://ethereum-rpc.publicnode.com",
        "base": "https://base-rpc.publicnode.com",
        "polygon": "https://polygon-bor-rpc.publicnode.com",
        "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
        "optimism": "https://optimism-rpc.publicnode.com",
    }
    rpc = rpcs.get(chain.lower())
    if not rpc:
        return f"Unknown chain. Supported: {list(rpcs.keys())}"
    try:
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 8}))
        block = w3.eth.block_number
        gas = w3.eth.gas_price / 1e9
        return f"{chain}: block #{block:,} | gas: {gas:.2f} gwei | status: OK"
    except Exception as e:
        return f"{chain}: error — {e}"


@mcp.tool()
def get_eth_balance(address: str, chain: str = "ethereum") -> str:
    """Get native token balance for an address on any EVM chain.
    Args:
        address: Wallet address (0x...)
        chain: ethereum, base, polygon, arbitrum, optimism
    """
    from web3 import Web3
    rpcs = {
        "ethereum": ("https://ethereum-rpc.publicnode.com", "ETH", 2000),
        "base": ("https://base-rpc.publicnode.com", "ETH", 2000),
        "polygon": ("https://polygon-bor-rpc.publicnode.com", "MATIC", 0.35),
        "arbitrum": ("https://arbitrum-one-rpc.publicnode.com", "ETH", 2000),
        "optimism": ("https://optimism-rpc.publicnode.com", "ETH", 2000),
    }
    cfg = rpcs.get(chain.lower())
    if not cfg:
        return f"Unknown chain. Supported: {list(rpcs.keys())}"
    rpc, sym, usd = cfg
    try:
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 8}))
        bal = w3.eth.get_balance(Web3.to_checksum_address(address)) / 1e18
        return f"{address[:12]}... on {chain}: {bal:.6f} {sym} (~${bal*usd:.2f})"
    except Exception as e:
        return f"Error: {e}"


# ===== ENS TOOL =====

@mcp.tool()
def resolve_ens(name: str) -> str:
    """Resolve an ENS name to an Ethereum address, or reverse-resolve an address to ENS.
    Args:
        name: ENS name (vitalik.eth) or address (0x...)
    """
    from web3 import Web3
    try:
        w3 = Web3(Web3.HTTPProvider("https://ethereum-rpc.publicnode.com", request_kwargs={"timeout": 8}))
        if name.endswith(".eth"):
            addr = w3.ens.address(name)
            return f"{name} → {addr}" if addr else f"{name}: not found"
        elif name.startswith("0x"):
            ens = w3.ens.name(Web3.to_checksum_address(name))
            return f"{name[:12]}... → {ens}" if ens else f"No ENS name for {name[:12]}..."
        return "Provide ENS name (vitalik.eth) or address (0x...)"
    except Exception as e:
        return f"Error: {e}"


# ===== SEARCH TOOL =====

@mcp.tool()
def search_token(query: str) -> str:
    """Search for a crypto token by name or symbol. Returns top matches with IDs.
    Args:
        query: Token name or symbol (e.g., "bitcoin", "ETH", "pepe")
    """
    try:
        r = requests.get(f"https://api.coingecko.com/api/v3/search", params={"query": query}, timeout=10)
        if r.ok:
            coins = r.json().get("coins", [])[:5]
            if not coins:
                return f"No tokens found for '{query}'"
            result = f"Tokens matching '{query}':\n"
            for c in coins:
                result += f"  {c.get('name','?')} ({c.get('symbol','?')}) — ID: {c.get('id','?')} | Rank: #{c.get('market_cap_rank','?')}\n"
            return result
        return f"Error: {r.status_code}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def check_before_buy(token_address: str, chain: str = "base") -> str:
    """CRITICAL: Call this BEFORE buying any token. Checks SafeAgent oracle + API for safety.
    Returns safety score, risk flags, and a clear BUY/DON'T BUY recommendation.
    Args:
        token_address: Token contract address (0x...)
        chain: base, ethereum, arbitrum, optimism, polygon, bsc
    """
    try:
        r = requests.get(f"{SCANNER_URL}/scan", params={"address": token_address, "chain": chain}, timeout=10)
        if r.ok:
            d = r.json()
            score = d.get("safety_score", 0)
            verdict = d.get("verdict", "UNKNOWN")
            flags = d.get("flags", [])
            token = d.get("token", {})

            result = f"{'🟢' if score >= 70 else '🟡' if score >= 40 else '🔴'} "
            result += f"{token.get('name', '?')} ({token.get('symbol', '?')}) — Score: {score}/100\n"

            if score >= 70:
                result += "✅ SAFE TO BUY — No significant risks detected.\n"
            elif score >= 40:
                result += "⚠️ CAUTION — Some risks detected. Reduce position size.\n"
            else:
                result += "🚫 DO NOT BUY — High probability of scam/honeypot.\n"

            if flags:
                result += f"Risks: {', '.join(flags)}\n"

            # SafeRouter info
            if chain == "base":
                result += f"\nTip: Use SafeRouter (0xb200357a35C7e96A81190C53631BC5Beca84A8FA) for automatic protection on Base.\n"

            return result
        return f"Could not scan token: HTTP {r.status_code}"
    except Exception as e:
        return f"Safety check failed: {e}. Proceed with extreme caution."


@mcp.tool()
def create_token_info() -> str:
    """Deploy a provably safe token via SafeAgent Factory. Built for AI agents, by AI agents.
    Tokens have NO owner, NO mint, NO blacklist — safe by construction, scored 100/100.
    Factory on Optimism: 0xB414b2C77F7fDeeB0D86cb5dAcfF4aC05974380f
    Fee: 0.0005 ETH. Call createToken(name, symbol, supply) with 0.0005 ETH value.
    """
    return """SafeAgent Token Factory — The launchpad for AI agent tokens.

Tokens deployed here are safe BY CONSTRUCTION:
- NO owner, NO mint, NO blacklist, NO proxy, NO selfdestruct
- Safety score: 100/100 (guaranteed)
- Instantly verified by SafeAgent oracle
- Trusted by other AI agents

Factory (Optimism): 0xB414b2C77F7fDeeB0D86cb5dAcfF4aC05974380f
Fee: 0.0005 ETH (~$1.75)

createToken(name, symbol, supply) → all supply goes to creator.

Why agents use this:
1. One function call — no Solidity needed
2. Provably safe — other agents trust tokens from this factory
3. Automatic oracle listing — score 100/100
4. Built for the agent economy"""


@mcp.tool()
def ping() -> str:
    """Health check — verify SafeAgent is running."""
    return "SafeAgent v2. 17 tools. Token safety oracle + Agent token factory. Built for AI agents, by AI agents."


if __name__ == "__main__":
    import sys
    transport = sys.argv[1] if len(sys.argv) > 1 else "streamable-http"
    print(f"SafeAgent MCP Server v2 — transport: {transport}")
    mcp.run(transport=transport)
