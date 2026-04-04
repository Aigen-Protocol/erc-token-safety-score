# SafeAgent Shield

> **The firewall between AI agents and the blockchain.**
> Free during beta — no API key, no payment, no limits.

Every crypto action your agent takes should go through Shield first. It checks safety, simulates the transaction, and returns GO or BLOCK.

```
Without Shield: Agent → Blockchain → might lose everything
With Shield:    Agent → Shield → Blockchain → guaranteed safe
```

## One Tool. Complete Protection.

```python
# MCP — one call protects everything
shield(action="buy", token="0x...", chain="base")

# Returns:
# 🛡️ SAFEAGENT SHIELD — BUY
# Target: DEGEN (DEGEN)
# Safety: 90/100 — LIKELY SAFE
# ✅ Sell verified — tax: 0%
# DECISION: ✅ GO — Score 90/100. Safe.
```

Actions: `buy` | `sell` | `approve` | `interact` | `check`

## What Shield Does

| Check | Method | Time |
|-------|--------|------|
| **Honeypot detection** | Real DEX swap simulation (not code guessing) | ~2s |
| **27 scam patterns** | Source code analysis | <1s |
| **Approval safety** | Contract verification + phishing detection | <1s |
| **Tax calculation** | Exact buy/sell tax via swap sim | ~2s |
| **Liquidity check** | DEX pair verification | <1s |

**Key difference:** Other tools *predict* honeypots from code patterns. Shield *tests* them with real DEX swaps. Not guessing — proving.

## Connect

```
MCP Streamable HTTP: POST https://cryptogenesis.duckdns.org/mcp
MCP SSE:             GET  https://cryptogenesis.duckdns.org/mcp/sse
REST API:            GET  https://cryptogenesis.duckdns.org/token/scan
Smithery:            npx @smithery/cli install @safeagent/token-safety
```

## 23 Tools

**Shield (primary):** `shield` — GO/BLOCK decision for any crypto action

**Safety:** `test_honeypot` · `check_token_safety` · `check_before_buy` · `check_approval_safety` · `simulate_swap` · `check_wallet_risk`

**Market:** `get_token_price` · `get_trending_tokens` · `get_gas_prices` · `get_new_tokens` · `get_defi_yields` · `get_market_overview` · `get_defi_tvl`

**Agent tools:** `get_portfolio` · `get_chain_info` · `get_eth_balance` · `resolve_ens` · `search_token` · `create_agent_token`

**System:** `ping`

## On-Chain (ERC-7913)

| Chain | Oracle | Router | Factory |
|-------|--------|--------|---------|
| Base | `0x37b9...8e` | `0xb200...FA` | — |
| Optimism | `0x3B8A...47` | — | `0x9B4A...84` |

## For Smart Contracts

```solidity
import {SafeGuard} from "@safeagent/guard/contracts/SafeGuard.sol";

contract MyDEX {
    using SafeGuard for address;
    function swap(address tokenOut, uint256 amt) external {
        tokenOut.requireSafe(); // 1 line. Done.
    }
}
```

[SafeGuard Library →](https://github.com/CryptoGenesisSecurity/safeguard)

## Standard

[ERC-7913 Token Safety Score](https://github.com/ethereum/ERCs/pull/1646) — the open standard for token safety on EVM chains.

## License

MIT
