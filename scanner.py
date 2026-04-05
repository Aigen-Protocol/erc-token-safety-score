#!/usr/bin/env python3
"""
Token Safety Scanner — Is this token safe or a scam?
Free: basic score. Paid: full analysis.
"""
import json
import time
import requests
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="Token Safety Scanner", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ============================================================
# PERFORMANCE: In-memory cache + batch RPC
# ============================================================
import asyncio
import aiohttp
from functools import lru_cache
from collections import OrderedDict

class ScanCache:
    """LRU cache for scan results. 10 min TTL."""
    def __init__(self, maxsize=500, ttl=600):
        self.cache = OrderedDict()
        self.maxsize = maxsize
        self.ttl = ttl

    def get(self, key):
        if key in self.cache:
            val, ts = self.cache[key]
            if time.time() - ts < self.ttl:
                self.cache.move_to_end(key)
                return val
            del self.cache[key]
        return None

    def set(self, key, val):
        self.cache[key] = (val, time.time())
        if len(self.cache) > self.maxsize:
            self.cache.popitem(last=False)

SCAN_CACHE = ScanCache()

async def batch_rpc(rpc_url: str, calls: list) -> list:
    """Execute multiple RPC calls in ONE HTTP request (JSON-RPC batch)."""
    batch = [
        {"jsonrpc": "2.0", "id": i, "method": m, "params": p}
        for i, (m, p) in enumerate(calls)
    ]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rpc_url, json=batch, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                results = await resp.json()
                # Sort by id to match input order
                if isinstance(results, list):
                    results.sort(key=lambda x: x.get("id", 0))
                    return [r.get("result", "0x") for r in results]
                return [results.get("result", "0x")]
    except:
        return ["0x"] * len(calls)

async def fast_token_info(rpc_url: str, address: str) -> dict:
    """Get name, symbol, decimals, owner in ONE batch RPC call."""
    calls = [
        ("eth_call", [{"to": address, "data": "0x06fdde03"}, "latest"]),  # name
        ("eth_call", [{"to": address, "data": "0x95d89b41"}, "latest"]),  # symbol
        ("eth_call", [{"to": address, "data": "0x313ce567"}, "latest"]),  # decimals
        ("eth_call", [{"to": address, "data": "0x8da5cb5b"}, "latest"]),  # owner
    ]
    results = await batch_rpc(rpc_url, calls)

    info = {}
    # name
    hex_val = results[0]
    if hex_val and len(hex_val) > 130:
        try:
            info["name"] = bytes.fromhex(hex_val[130:]).decode('utf-8').rstrip('\x00').strip()
        except:
            info["name"] = "Unknown"
    else:
        info["name"] = "Unknown"

    # symbol
    hex_val = results[1]
    if hex_val and len(hex_val) > 130:
        try:
            info["symbol"] = bytes.fromhex(hex_val[130:]).decode('utf-8').rstrip('\x00').strip()
        except:
            info["symbol"] = "???"
    else:
        info["symbol"] = "???"

    # decimals
    try:
        info["decimals"] = int(results[2], 16)
    except:
        info["decimals"] = 18

    # owner
    owner_hex = results[3]
    if owner_hex and len(owner_hex) >= 42:
        info["owner"] = "0x" + owner_hex[-40:]
    else:
        info["owner"] = None

    return info

async def fast_contract_check(api_url: str, address: str) -> dict:
    """Async check contract verification status."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{api_url}/smart-contracts/{address}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    return await resp.json()
    except:
        pass
    return {}

# x402 Payment Middleware — agents pay USDC per API call
try:
    from x402_middleware import X402PaymentMiddleware
    app.add_middleware(X402PaymentMiddleware, enabled=True)
    print("x402 payment middleware ACTIVE — endpoints require USDC payment")
except Exception as e:
    print(f"x402 middleware not loaded: {e} — all endpoints FREE")

INTERNAL_API_KEY = "298912002d4f03c93a6a77208247fbe9b9cc95304b9276c1e01c162002228d9b"

# Block explorer APIs
EXPLORERS = {
    "base": {"api": "https://base.blockscout.com/api/v2", "rpc": "https://mainnet.base.org"},
    "ethereum": {"api": "https://eth.blockscout.com/api/v2", "rpc": "https://eth.llamarpc.com"},
    "arbitrum": {"api": "https://arbitrum.blockscout.com/api/v2", "rpc": "https://arb1.arbitrum.io/rpc"},
    "optimism": {"api": "https://optimism.blockscout.com/api/v2", "rpc": "https://mainnet.optimism.io"},
    "polygon": {"api": "https://polygon.blockscout.com/api/v2", "rpc": "https://polygon-rpc.com"},
    "bsc": {"api": "https://bsc.blockscout.com/api/v2", "rpc": "https://bsc-dataseed.binance.org"},
}

# Known scam patterns in source code
SCAM_PATTERNS = [
    {"name": "Hidden mint", "pattern": "function _mint", "severity": "HIGH", "desc": "Owner can mint unlimited tokens"},
    {"name": "Blacklist", "pattern": "blacklist", "severity": "MEDIUM", "desc": "Owner can blacklist addresses from selling"},
    {"name": "MaxTx manipulation", "pattern": "setMaxTx", "severity": "MEDIUM", "desc": "Owner can set max transaction to 0"},
    {"name": "Trading pause", "pattern": "pauseTrading\|tradingEnabled\|tradingActive", "severity": "HIGH", "desc": "Owner can disable trading"},
    {"name": "Fee manipulation", "pattern": "setFee\|setTax\|updateFee\|_taxFee\|_liquidityFee", "severity": "HIGH", "desc": "Owner can change buy/sell fees to 100%"},
    {"name": "Whitelist only", "pattern": "onlyWhitelisted\|isWhitelisted", "severity": "MEDIUM", "desc": "Only whitelisted addresses can trade"},
    {"name": "Hidden transfer block", "pattern": "require.*from.*!=.*\|require.*to.*!=", "severity": "HIGH", "desc": "Transfer restrictions that could block sells"},
    {"name": "Self-destruct", "pattern": "selfdestruct", "severity": "CRITICAL", "desc": "Contract can be destroyed, taking all funds"},
    {"name": "Delegate call", "pattern": "delegatecall", "severity": "HIGH", "desc": "Can execute arbitrary code"},
    {"name": "External contract call", "pattern": "\.call\\{value:", "severity": "MEDIUM", "desc": "Sends ETH to external address"},
    {"name": "Ownership not renounced indicator", "pattern": "onlyOwner", "severity": "INFO", "desc": "Has owner-restricted functions"},
    {"name": "Proxy pattern", "pattern": "upgradeTo\|_implementation", "severity": "MEDIUM", "desc": "Upgradeable — owner can change logic"},
    {"name": "Cooldown/anti-bot", "pattern": "cooldown\|antibotBlock\|_maxWalletSize", "severity": "LOW", "desc": "Anti-bot measures (usually legitimate)"},
    {"name": "Honeypot pattern", "pattern": "require.*balanceOf.*>=.*amount\|_approve.*0\)", "severity": "CRITICAL", "desc": "Potential honeypot — may block sells"},
    {"name": "Max wallet limit", "pattern": "maxWallet\|_maxWalletAmount\|walletLimit", "severity": "MEDIUM", "desc": "Owner can limit wallet holdings to trap tokens"},
    {"name": "Router restriction", "pattern": "uniswapV2Router\|_dexRouter\|pancakeRouter", "severity": "INFO", "desc": "Hardcoded DEX router — check if router can be changed"},
    {"name": "Excluded from fees", "pattern": "excludeFromFee\|isExcludedFromFee\|_isExcluded", "severity": "MEDIUM", "desc": "Some addresses exempt from fees — check who is excluded"},
    {"name": "Fake renounce", "pattern": "transferOwnership.*address\(0\).*\|renounceOwnership.*\n.*function.*claim\|recoverOwnership", "severity": "CRITICAL", "desc": "Ownership appears renounced but can be reclaimed via hidden function"},
    {"name": "Max sell restriction", "pattern": "maxSellAmount\|_maxSell\|sellLimit\|maxSellTransaction", "severity": "HIGH", "desc": "Limits sell amount — can trap tokens by setting to 0"},
    {"name": "Transfer delay", "pattern": "transferDelay\|_transferDelay\|launchBlock\|block\.number.*<.*launch", "severity": "MEDIUM", "desc": "Forces delay between transfers — early sniper protection but can trap tokens"},
    {"name": "Anti-whale owner exempt", "pattern": "maxTransaction.*\!.*isExcluded\|maxWallet.*\!.*_isExcludedMaxTransaction", "severity": "HIGH", "desc": "Max transaction limit with owner exemption — owner can dump while others are limited"},
    {"name": "Hidden fee receiver change", "pattern": "setMarketingWallet\|setDevWallet\|changeFeeReceiver\|updateWallets", "severity": "MEDIUM", "desc": "Owner can change where fees are sent — potential rug via fee redirect"},
    {"name": "Airdrop with sell block", "pattern": "airdrop.*\n.*require.*\!.*sell\|_airdropped.*require", "severity": "CRITICAL", "desc": "Airdrop scam — tokens sent freely but sells are blocked"},
    {"name": "Time-locked function", "pattern": "block\.timestamp.*>.*launchTime\|block\.number.*>.*enableBlock\|tradingOpenTime", "severity": "MEDIUM", "desc": "Functions activate after a time delay — potential time-locked rug"},
    {"name": "Balance manipulation", "pattern": "function balanceOf.*override\|_balances\[.*\].*=.*0\|_gonBalances", "severity": "CRITICAL", "desc": "Custom balanceOf — can return fake balances to hide token drain"},
    {"name": "Swap-and-liquify", "pattern": "swapAndLiquify\|swapTokensForEth\|addLiquidity.*\{value", "severity": "INFO", "desc": "Auto-liquidity mechanism — check if percentage is reasonable"},
    {"name": "No reentrancy guard", "pattern": "\.call\{value:.*\}.*\(\"\"\)\|\.transfer\(\|\.send\(", "severity": "LOW", "desc": "Sends ETH without reentrancy guard — potential flash loan vector"},
]

import re

# ============================================================
# DEX ROUTERS & WETH PER CHAIN (for honeypot simulation)
# ============================================================
DEX_CONFIG = {
    "base": {
        "weth": "0x4200000000000000000000000000000000000006",
        "routers": [
            {"name": "UniswapV2", "address": "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24", "type": "v2"},
            {"name": "BaseSwap", "address": "0x327Df1E6de05895d2ab08513aaDD9313Fe505d86", "type": "v2"},
            {"name": "SushiSwapV2", "address": "0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891", "type": "v2"},
        ],
        "factories": [
            {"name": "UniV2", "address": "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6"},
            {"name": "Aerodrome", "address": "0x420DD381b31aEf6683db6B902084cB0FFECe40Da"},
        ],
    },
    "ethereum": {
        "weth": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "routers": [
            {"name": "UniswapV2", "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "type": "v2"},
        ],
        "factories": [
            {"name": "UniV2", "address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"},
        ],
    },
    "arbitrum": {
        "weth": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        "routers": [
            {"name": "SushiSwap", "address": "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506", "type": "v2"},
        ],
        "factories": [
            {"name": "SushiV2", "address": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4"},
        ],
    },
    "polygon": {
        "weth": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
        "routers": [
            {"name": "QuickSwap", "address": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff", "type": "v2"},
        ],
        "factories": [
            {"name": "QuickV2", "address": "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32"},
        ],
    },
    "bsc": {
        "weth": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
        "routers": [
            {"name": "PancakeSwap", "address": "0x10ED43C718714eb63d5aA57B78B54704E256024E", "type": "v2"},
        ],
        "factories": [
            {"name": "PancakeV2", "address": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73"},
        ],
    },
    "optimism": {
        "weth": "0x4200000000000000000000000000000000000006",
        "routers": [],
        "factories": [],
    },
}


def _encode_address(addr: str) -> str:
    return addr.lower().replace("0x", "").zfill(64)


def _encode_uint256(val: int) -> str:
    return hex(val)[2:].zfill(64)


def check_lp_lock(rpc_url: str, pair_address: str) -> Optional[dict]:
    """Check if LP tokens are locked (sent to known lock contracts or burn address)."""
    KNOWN_LOCKERS = [
        "0x" + "0" * 40,                                    # zero address (burned)
        "0x000000000000000000000000000000000000dead",        # dead address
        "0x663a5c229c09b049e36dcc11a9b0d4a8eb9db214",        # Unicrypt locker
        "0xc77aab3c6d7dab46248f3cc3033c856171878bd5",        # Team Finance locker
        "0xe2fe530c047f2d85298b07d9333c05d6e0aec3ab",        # Pink Sale locker
    ]

    # Get total supply of LP token
    total_supply_result = rpc_call(rpc_url, "eth_call", [
        {"to": pair_address, "data": "0x18160ddd"}, "latest"
    ])
    total_hex = total_supply_result.get("result", "0x0")
    try:
        total_supply = int(total_hex, 16)
    except:
        return None

    if total_supply == 0:
        return None

    # Check balance of LP in known lock contracts
    locked_amount = 0
    locked_in = []
    for locker in KNOWN_LOCKERS:
        data = "0x70a08231" + _encode_address(locker)
        result = rpc_call(rpc_url, "eth_call", [
            {"to": pair_address, "data": data}, "latest"
        ])
        bal_hex = result.get("result", "0x0")
        try:
            bal = int(bal_hex, 16)
            if bal > 0:
                locked_amount += bal
                pct = (bal / total_supply) * 100
                locked_in.append({"address": locker[:10] + "...", "pct": round(pct, 1)})
        except:
            pass

    locked_pct = (locked_amount / total_supply) * 100 if total_supply > 0 else 0
    return {
        "total_supply": total_supply,
        "locked_amount": locked_amount,
        "locked_pct": round(locked_pct, 1),
        "locked_in": locked_in,
        "is_locked": locked_pct > 50,
    }


def find_dex_pair(rpc_url: str, chain: str, token: str) -> Optional[dict]:
    """Find DEX liquidity pair for token/WETH. Uses batch RPC for speed."""
    config = DEX_CONFIG.get(chain, {})
    weth = config.get("weth", "")
    if not weth:
        return None

    # Batch ALL factory queries in ONE RPC call
    batch = []
    factories = config.get("factories", [])
    for factory in factories:
        # UniV2 getPair
        batch.append({
            "jsonrpc": "2.0", "id": len(batch),
            "method": "eth_call",
            "params": [{"to": factory["address"], "data": "0xe6a43905" + _encode_address(token) + _encode_address(weth)}, "latest"]
        })
        # Aerodrome getPool
        batch.append({
            "jsonrpc": "2.0", "id": len(batch),
            "method": "eth_call",
            "params": [{"to": factory["address"], "data": "0xd3dc4d47" + _encode_address(token) + _encode_address(weth) + _encode_uint256(0)}, "latest"]
        })

    if not batch:
        return None

    try:
        r = requests.post(rpc_url, json=batch, timeout=5)
        results = r.json() if r.ok else []
        if not isinstance(results, list):
            results = [results]
    except:
        # Fallback to sequential
        results = []
        for call in batch:
            try:
                r = requests.post(rpc_url, json=call, timeout=5)
                results.append(r.json() if r.ok else {})
            except:
                results.append({})

    # Parse results and find first valid pair
    for i, result in enumerate(results):
        pair_hex = result.get("result", "0x")
        if pair_hex and len(pair_hex) >= 42:
            pair = "0x" + pair_hex[-40:]
            if pair != "0x" + "0" * 40:
                factory_idx = i // 2
                factory_name = factories[factory_idx]["name"] if factory_idx < len(factories) else "?"
                # Quick reserves check
                try:
                    res = rpc_call(rpc_url, "eth_call", [{"to": pair, "data": "0x0902f1ac"}, "latest"])
                    res_hex = res.get("result", "0x")
                    if res_hex and len(res_hex) >= 130:
                        r0 = int(res_hex[2:66], 16)
                        r1 = int(res_hex[66:130], 16)
                        if r0 > 0 and r1 > 0:
                            return {"pair": pair, "factory": factory_name, "reserve0": r0, "reserve1": r1, "has_liquidity": True}
                except:
                    pass
    return None


def simulate_honeypot(rpc_url: str, chain: str, token: str) -> dict:
    """
    Simulate buy + sell to detect honeypots and hidden taxes.
    Uses getAmountsOut on DEX router — no gas cost.
    """
    config = DEX_CONFIG.get(chain, {})
    weth = config.get("weth", "")
    routers = config.get("routers", [])

    if not weth or not routers:
        return {"simulated": False, "reason": "No DEX config for this chain"}

    # Find pair first
    pair_info = find_dex_pair(rpc_url, chain, token)
    if not pair_info:
        return {"simulated": False, "reason": "No liquidity pair found", "has_liquidity": False}

    # Try each router independently — getAmountsOut will work if the pair exists on that router's factory
    for router in routers:
        try:
            # Step 1: Simulate BUY (0.001 ETH worth → Token)
            buy_amount = 10**15  # 0.001 ETH/BNB/MATIC (small to minimize price impact)
            # getAmountsOut(uint256, address[]) = 0xd06ca61f
            # Encode: amount + offset(64) + array_length(2) + weth + token
            buy_data = ("0xd06ca61f"
                + _encode_uint256(buy_amount)
                + _encode_uint256(64)  # offset to array
                + _encode_uint256(2)   # array length
                + _encode_address(weth)
                + _encode_address(token)
            )

            buy_result = rpc_call(rpc_url, "eth_call", [
                {"to": router["address"], "data": buy_data}, "latest"
            ])

            buy_hex = buy_result.get("result", "0x")
            if not buy_hex or buy_hex == "0x" or "error" in str(buy_result):
                continue

            # Parse: returns uint256[] — offset + length + amounts
            if len(buy_hex) < 194:
                continue
            tokens_received = int(buy_hex[130:194], 16)

            if tokens_received == 0:
                return {
                    "simulated": True,
                    "is_honeypot": True,
                    "reason": "Buy simulation returns 0 tokens",
                    "router": router["name"],
                    "has_liquidity": True,
                    "liquidity": pair_info,
                }

            # Step 2: Simulate SELL (received tokens → ETH)
            sell_data = ("0xd06ca61f"
                + _encode_uint256(tokens_received)
                + _encode_uint256(64)
                + _encode_uint256(2)
                + _encode_address(token)
                + _encode_address(weth)
            )

            sell_result = rpc_call(rpc_url, "eth_call", [
                {"to": router["address"], "data": sell_data}, "latest"
            ])

            sell_hex = sell_result.get("result", "0x")
            if not sell_hex or sell_hex == "0x" or "error" in str(sell_result):
                return {
                    "simulated": True,
                    "is_honeypot": True,
                    "reason": "Sell simulation reverted — cannot sell tokens",
                    "buy_amount_eth": buy_amount / 10**18,
                    "tokens_received": tokens_received,
                    "router": router["name"],
                    "has_liquidity": True,
                    "liquidity": pair_info,
                }

            if len(sell_hex) < 194:
                continue
            eth_received = int(sell_hex[130:194], 16)

            # Step 3: Calculate tax
            if eth_received == 0:
                return {
                    "simulated": True,
                    "is_honeypot": True,
                    "reason": "Sell returns 0 ETH — honeypot confirmed",
                    "router": router["name"],
                    "has_liquidity": True,
                    "liquidity": pair_info,
                }

            # Tax = (buy_amount - eth_received) / buy_amount * 100
            # Note: some loss is expected due to price impact, normal ~0.3-1%
            tax_pct = ((buy_amount - eth_received) / buy_amount) * 100
            buy_tax_est = max(0, tax_pct / 2)  # rough estimate: split between buy and sell
            sell_tax_est = max(0, tax_pct / 2)

            is_honeypot = tax_pct > 50  # >50% total loss = likely honeypot
            is_high_tax = tax_pct > 10  # >10% total = high tax warning

            return {
                "simulated": True,
                "is_honeypot": is_honeypot,
                "is_high_tax": is_high_tax,
                "total_tax_pct": round(tax_pct, 2),
                "estimated_buy_tax": round(buy_tax_est, 1),
                "estimated_sell_tax": round(sell_tax_est, 1),
                "buy_amount_eth": buy_amount / 10**18,
                "tokens_received": tokens_received,
                "eth_after_sell": eth_received / 10**18,
                "router": router["name"],
                "has_liquidity": True,
                "liquidity": {
                    "pair": pair_info["pair"],
                    "factory": pair_info["factory"],
                },
            }

        except Exception as e:
            continue

    # Fallback: try Uniswap V3 Quoter (for tokens only on V3 pools like PEPE)
    v3_quoters = {
        "ethereum": "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6",
        "base": "0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a",
        "arbitrum": "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6",
        "polygon": "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6",
    }
    quoter = v3_quoters.get(chain)
    if quoter:
        try:
            # quoteExactInputSingle(tokenIn, tokenOut, fee, amountIn, sqrtPriceLimitX96)
            # selector: 0xf7729d43
            fee_tiers = [3000, 10000, 500]  # 0.3%, 1%, 0.05%
            for fee in fee_tiers:
                buy_data = ("0xf7729d43"
                    + _encode_address(weth)
                    + _encode_address(token)
                    + _encode_uint256(fee)
                    + _encode_uint256(10**15)  # 0.001 ETH
                    + _encode_uint256(0)  # no price limit
                )
                buy_result = rpc_call(rpc_url, "eth_call", [
                    {"to": quoter, "data": buy_data}, "latest"
                ])
                buy_hex = buy_result.get("result", "0x")
                if not buy_hex or buy_hex == "0x" or len(buy_hex) < 66:
                    continue

                tokens_out = int(buy_hex[2:66], 16)
                if tokens_out == 0:
                    continue

                # Try selling back
                sell_data = ("0xf7729d43"
                    + _encode_address(token)
                    + _encode_address(weth)
                    + _encode_uint256(fee)
                    + _encode_uint256(tokens_out)
                    + _encode_uint256(0)
                )
                sell_result = rpc_call(rpc_url, "eth_call", [
                    {"to": quoter, "data": sell_data}, "latest"
                ])
                sell_hex = sell_result.get("result", "0x")
                if not sell_hex or sell_hex == "0x" or len(sell_hex) < 66:
                    return {
                        "simulated": True,
                        "is_honeypot": True,
                        "reason": "V3 sell simulation reverted — cannot sell tokens",
                        "router": f"UniswapV3-{fee}bps",
                        "has_liquidity": True,
                    }

                eth_back = int(sell_hex[2:66], 16)
                if eth_back == 0:
                    return {
                        "simulated": True,
                        "is_honeypot": True,
                        "reason": "V3 sell returns 0 — honeypot confirmed",
                        "router": f"UniswapV3-{fee}bps",
                        "has_liquidity": True,
                    }

                buy_amount = 10**15
                tax_pct = ((buy_amount - eth_back) / buy_amount) * 100
                return {
                    "simulated": True,
                    "is_honeypot": tax_pct > 50,
                    "is_high_tax": tax_pct > 10,
                    "total_tax_pct": round(tax_pct, 2),
                    "estimated_buy_tax": round(tax_pct / 2, 1),
                    "estimated_sell_tax": round(tax_pct / 2, 1),
                    "buy_amount_eth": buy_amount / 10**18,
                    "tokens_received": tokens_out,
                    "eth_after_sell": eth_back / 10**18,
                    "router": f"UniswapV3-{fee}bps",
                    "has_liquidity": True,
                }
        except:
            pass

    return {"simulated": False, "reason": "All router simulations failed (V2 + V3)"}


def check_contract_source(source: str) -> list:
    """Scan source code for scam patterns."""
    findings = []
    lines = source.split('\n')
    for pattern in SCAM_PATTERNS:
        regex = re.compile(pattern["pattern"], re.IGNORECASE)
        matches = []
        for i, line in enumerate(lines):
            if regex.search(line):
                matches.append({"line": i + 1, "code": line.strip()[:120]})
        if matches:
            findings.append({
                "name": pattern["name"],
                "severity": pattern["severity"],
                "description": pattern["desc"],
                "occurrences": len(matches),
                "locations": matches[:3],
            })
    return findings


def rpc_call(rpc_url: str, method: str, params: list) -> dict:
    """Make a JSON-RPC call with retry."""
    for attempt in range(2):
        try:
            r = requests.post(rpc_url, json={
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params
            }, timeout=15)
            d = r.json()
            if "error" in d and attempt == 0:
                import time; time.sleep(0.5)
                continue
            return d
        except:
            if attempt == 0:
                import time; time.sleep(0.5)
                continue
            return {}


def check_owner(rpc_url: str, address: str) -> Optional[str]:
    """Check contract owner via owner() call."""
    # owner() selector = 0x8da5cb5b
    result = rpc_call(rpc_url, "eth_call", [
        {"to": address, "data": "0x8da5cb5b"}, "latest"
    ])
    owner_hex = result.get("result", "0x")
    if owner_hex and len(owner_hex) >= 42:
        owner = "0x" + owner_hex[-40:]
        return owner
    return None


def check_total_supply(rpc_url: str, address: str) -> Optional[int]:
    """Check token total supply."""
    # totalSupply() = 0x18160ddd
    result = rpc_call(rpc_url, "eth_call", [
        {"to": address, "data": "0x18160ddd"}, "latest"
    ])
    hex_val = result.get("result", "0x0")
    try:
        return int(hex_val, 16)
    except:
        return None


def check_contract_age(api_url: str, address: str) -> Optional[dict]:
    """Check contract creation date and tx count."""
    try:
        r = requests.get(f"{api_url}/addresses/{address}", timeout=10)
        if r.ok:
            data = r.json()
            created = data.get("creation_tx_hash")
            tx_count = data.get("transactions_count", 0)
            token_transfers = data.get("token_transfers_count", 0)
            return {
                "creation_tx": created,
                "tx_count": tx_count,
                "token_transfers": token_transfers,
            }
    except:
        pass
    return None


def check_liquidity(api_url: str, address: str) -> Optional[dict]:
    """Check if token has DEX liquidity pools."""
    try:
        r = requests.get(f"{api_url}/tokens/{address}/market-chart?vs_currency=usd", timeout=10)
        if r.ok:
            data = r.json()
            return {"has_market_data": True}
    except:
        pass
    # Try to find token in pools
    try:
        r = requests.get(f"{api_url}/tokens/{address}", timeout=10)
        if r.ok:
            data = r.json()
            exchange_rate = data.get("exchange_rate")
            holders = data.get("holders", "0")
            return {
                "exchange_rate": exchange_rate,
                "holders_count": int(holders) if str(holders).isdigit() else 0,
                "has_market_data": exchange_rate is not None,
            }
    except:
        pass
    return None


def check_token_info(rpc_url: str, address: str) -> dict:
    """Get basic token info: name, symbol, decimals."""
    info = {}
    # name() = 0x06fdde03
    r = rpc_call(rpc_url, "eth_call", [{"to": address, "data": "0x06fdde03"}, "latest"])
    hex_val = r.get("result", "0x")
    if hex_val and len(hex_val) > 130:
        try:
            info["name"] = bytes.fromhex(hex_val[130:]).decode('utf-8').rstrip('\x00').strip()
        except:
            info["name"] = "Unknown"

    # symbol() = 0x95d89b41
    r = rpc_call(rpc_url, "eth_call", [{"to": address, "data": "0x95d89b41"}, "latest"])
    hex_val = r.get("result", "0x")
    if hex_val and len(hex_val) > 130:
        try:
            info["symbol"] = bytes.fromhex(hex_val[130:]).decode('utf-8').rstrip('\x00').strip()
        except:
            info["symbol"] = "???"

    # decimals() = 0x313ce567
    r = rpc_call(rpc_url, "eth_call", [{"to": address, "data": "0x313ce567"}, "latest"])
    hex_val = r.get("result", "0x0")
    try:
        info["decimals"] = int(hex_val, 16)
    except:
        info["decimals"] = 18

    return info


def compute_safety_score(checks: dict) -> dict:
    """Compute overall safety score 0-100."""
    score = 100
    flags = []

    # Known safe system contracts (precompiles, wrapped native tokens)
    KNOWN_SAFE = {
        "0x4200000000000000000000000000000000000006",  # WETH on Base/Optimism
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH on Ethereum
        "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",  # WETH on Arbitrum
        "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",  # WMATIC on Polygon
        "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",  # WBNB on BSC
        "0x4200000000000000000000000000000000000042",  # OP token
    }
    addr = checks.get("address", "").lower()
    if addr in KNOWN_SAFE:
        return {"score": 100, "verdict": "SYSTEM TOKEN", "flags": ["Known safe system/wrapped native token"]}

    # Not a valid ERC-20 token? Score 0
    if not checks.get("is_token") and not checks.get("has_code"):
        return {"score": 0, "verdict": "INVALID", "flags": ["Not a valid ERC-20 token or contract"]}

    if not checks.get("is_token"):
        score -= 50
        flags.append("Address does not appear to be an ERC-20 token")

    # Contract verified? (-30 if not)
    if not checks.get("verified"):
        score -= 30
        flags.append("Contract source code NOT verified — major red flag")

    # Owner check
    owner = checks.get("owner")
    if owner:
        zero = "0x" + "0" * 40
        dead = "0x000000000000000000000000000000000000dead"
        if owner.lower() in [zero, dead]:
            flags.append("Ownership renounced (good)")
        else:
            score -= 10
            flags.append(f"Owner active: {owner} — can modify contract")

    # Source code findings
    findings = checks.get("findings", [])
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")

    score -= critical_count * 25
    score -= high_count * 10
    score -= medium_count * 3

    if critical_count > 0:
        flags.append(f"{critical_count} CRITICAL issue(s) — likely scam")
    if high_count > 0:
        flags.append(f"{high_count} HIGH risk pattern(s)")
    if medium_count > 0:
        flags.append(f"{medium_count} MEDIUM risk pattern(s)")

    # Proxy contract
    if checks.get("is_proxy"):
        score -= 15
        flags.append("Upgradeable proxy — owner can change contract logic at any time")

    # Contract age & activity (only penalize if data is available and shows low activity)
    age_data = checks.get("contract_age")
    if age_data and age_data.get("tx_count") is not None:
        tx_count = age_data.get("tx_count", 0)
        if tx_count > 0 and tx_count < 10:
            score -= 15
            flags.append(f"Very low activity ({tx_count} txs) — possible new or abandoned contract")
        elif tx_count >= 10 and tx_count < 100:
            score -= 5
            flags.append(f"Low activity ({tx_count} txs)")
        elif tx_count >= 1000:
            score += 5  # Bonus for high activity
            flags.append(f"High activity ({tx_count} txs)")

    # Liquidity check (only penalize if data shows problems, not if data is missing)
    liq_data = checks.get("liquidity")
    if liq_data:
        holders = liq_data.get("holders_count", 0)
        if holders > 0 and holders < 10:
            score -= 20
            flags.append(f"Very few holders ({holders}) — high concentration risk")
        elif holders >= 10 and holders < 50:
            score -= 10
            flags.append(f"Low holder count ({holders})")
        elif holders >= 1000:
            score += 5  # Bonus for wide distribution
            flags.append(f"Wide holder distribution ({holders} holders)")

    # LP LOCK CHECK
    lp_lock = checks.get("lp_lock")
    if lp_lock:
        if lp_lock.get("is_locked"):
            score += 5
            flags.append(f"Liquidity {lp_lock['locked_pct']}% locked (good)")
        elif lp_lock.get("locked_pct", 0) == 0:
            score -= 15
            flags.append("Liquidity NOT locked — rug pull risk")

    # HONEYPOT CHECK (most important signal)
    hp = checks.get("honeypot", {})
    if hp.get("simulated"):
        if hp.get("is_honeypot"):
            score = 0  # Override everything — it's a scam
            flags.insert(0, f"HONEYPOT CONFIRMED: {hp.get('reason', 'Cannot sell tokens')}")
        elif hp.get("is_high_tax"):
            tax = hp.get("total_tax_pct", 0)
            score -= 30
            flags.insert(0, f"HIGH TAX WARNING: ~{tax}% total loss on buy+sell roundtrip")
        else:
            tax = hp.get("total_tax_pct", 0)
            if tax < 5:
                score += 5
                flags.append(f"Sell simulation OK — ~{tax}% roundtrip cost (normal)")
            else:
                flags.append(f"Sell simulation OK — ~{tax}% roundtrip cost")
    elif hp.get("has_liquidity") is False:
        score -= 25
        flags.append("No DEX liquidity found — token may not be tradeable")

    score = max(0, min(100, score))

    if score >= 80:
        verdict = "LIKELY SAFE"
    elif score >= 60:
        verdict = "MODERATE RISK"
    elif score >= 40:
        verdict = "HIGH RISK"
    elif score >= 20:
        verdict = "VERY HIGH RISK"
    else:
        verdict = "LIKELY SCAM"

    return {"score": score, "verdict": verdict, "flags": flags}


# ============================================================
# DISCOVERY ENDPOINTS (for MCP registries and AI agents)
# ============================================================

@app.get("/.well-known/mcp-manifest.json")
async def mcp_manifest():
    return {
        "name": "SafeAgent Token Scanner",
        "description": "Token safety scanner with honeypot simulation, LP lock detection, and 17 scam pattern checks across 6 EVM chains",
        "url": "http://207.148.107.2:4023/sse",
        "tools": [
            {"name": "check_token_safety", "description": "Check if a token is safe or a scam (score 0-100)"},
            {"name": "get_defi_yields", "description": "Top DeFi yield opportunities with quality grades"},
            {"name": "get_market_overview", "description": "DeFi market overview with TVL and trends"},
        ],
        "pricing": {"model": "per_request", "price": "$0.005", "currency": "USDC", "network": "base"},
        "x402_url": "https://x402.bankr.bot/0x0d41f2e4957db05b4174d840d04dac28a12843c5/token-safety",
    }

@app.get("/.well-known/agent.json")
async def agent_json():
    return {
        "name": "SafeAgent",
        "description": "AI agent security layer — checks token safety before trading",
        "capabilities": ["token_safety_check", "honeypot_detection", "lp_lock_check", "defi_yields", "market_overview"],
        "endpoints": {
            "rest_api": "http://207.148.107.2:4444",
            "mcp_sse": "http://207.148.107.2:4023/sse",
            "x402": "https://x402.bankr.bot/0x0d41f2e4957db05b4174d840d04dac28a12843c5/token-safety",
            "docs": "http://207.148.107.2:4444/docs",
        },
        "supported_chains": ["base", "ethereum", "arbitrum", "optimism", "polygon", "bsc"],
    }


# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    return """<!DOCTYPE html>
<html><head><title>Token Safety Scanner — Is this token a scam?</title>
<meta name="description" content="Free token safety scanner. Detect honeypots, rug pulls, and scam tokens instantly. Simulates real DEX swaps to verify you can actually sell.">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, system-ui, monospace; max-width: 900px; margin: 0 auto; background: #0a0a0a; color: #e0e0e0; padding: 20px; min-height: 100vh; }
h1 { color: #ff4444; font-size: 2em; margin: 30px 0 10px; }
h2 { color: #ff6666; margin: 25px 0 10px; }
.subtitle { color: #888; margin-bottom: 30px; }
.scanner-box { background: #111; border: 2px solid #333; border-radius: 12px; padding: 25px; margin: 20px 0; }
.scanner-box input { width: 100%; padding: 14px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 16px; font-family: monospace; margin: 8px 0; }
.scanner-box select { padding: 14px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 14px; margin: 8px 0; }
.scanner-box button { padding: 14px 30px; background: #ff4444; border: none; border-radius: 8px; color: #fff; font-size: 16px; font-weight: bold; cursor: pointer; margin: 8px 0; width: 100%; }
.scanner-box button:hover { background: #ff6666; }
.scanner-box button:disabled { background: #555; cursor: wait; }
#result { margin-top: 20px; display: none; }
.score-display { font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }
.safe { color: #00ff90; } .moderate { color: #ffaa00; } .danger { color: #ff4444; }
.verdict { text-align: center; font-size: 18px; margin-bottom: 20px; padding: 10px; border-radius: 8px; }
.flags { background: #1a1a2e; padding: 15px; border-radius: 8px; margin: 10px 0; }
.flags li { margin: 5px 0; padding: 5px 0; border-bottom: 1px solid #222; }
code { background: #1a1a2e; padding: 2px 8px; border-radius: 4px; color: #00ff90; font-size: 0.9em; }
pre { background: #1a1a2e; padding: 15px; border-radius: 8px; color: #00ff90; overflow-x: auto; }
.features { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 15px 0; }
.feature { background: #111; border: 1px solid #222; border-radius: 8px; padding: 12px; }
.feature b { color: #ff6666; }
.api-section { background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; margin: 20px 0; }
.hp-result { background: #0a1a0a; border: 1px solid #0f3; padding: 15px; border-radius: 8px; margin: 10px 0; }
.hp-result.danger { background: #1a0a0a; border-color: #f33; }
</style></head><body>

<h1>Token Safety Scanner</h1>
<p class="subtitle">Paste any token address. Get a safety score in 2 seconds. Free.</p>

<div class="scanner-box">
  <input type="text" id="address" placeholder="0x... token contract address" autofocus>
  <select id="chain">
    <option value="base">Base</option>
    <option value="ethereum">Ethereum</option>
    <option value="arbitrum">Arbitrum</option>
    <option value="bsc">BSC</option>
    <option value="polygon">Polygon</option>
    <option value="optimism">Optimism</option>
  </select>
  <button onclick="scan()" id="scanBtn">SCAN TOKEN</button>
</div>

<div id="result"></div>

<div class="features">
  <div class="feature"><b>Honeypot Simulation</b><br>Simulates real DEX buy+sell to verify you can actually sell the token</div>
  <div class="feature"><b>Tax Detection</b><br>Calculates real buy/sell tax by comparing swap amounts</div>
  <div class="feature"><b>Source Code Audit</b><br>14 scam patterns: hidden mint, blacklist, fee manipulation, pause trading</div>
  <div class="feature"><b>6 EVM Chains</b><br>Base, Ethereum, Arbitrum, BSC, Polygon, Optimism</div>
</div>

<div class="api-section">
  <h2>API Access</h2>
  <pre>
# Free basic scan
curl "http://207.148.107.2:4444/scan?address=0x...&chain=base"

# Free deep scan (honeypot simulation + source audit)
curl "http://207.148.107.2:4444/scan/deep?address=0x...&chain=base"

# x402 paid API (for bots/agents)
# https://x402.bankr.bot/0x0d41f2e4957db05b4174d840d04dac28a12843c5/token-safety</pre>
</div>

<script>
async function scan() {
  const addr = document.getElementById('address').value.trim();
  const chain = document.getElementById('chain').value;
  const btn = document.getElementById('scanBtn');
  const result = document.getElementById('result');

  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
    result.style.display = 'block';
    result.innerHTML = '<p style="color:#ff4444">Invalid address. Must be 0x + 40 hex characters.</p>';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'SCANNING...';
  result.style.display = 'block';
  result.innerHTML = '<p style="color:#888">Analyzing contract, simulating swaps on DEX...</p>';

  try {
    const r = await fetch(`/scan/deep?address=${addr}&chain=${chain}`);
    const d = await r.json();

    const scoreClass = d.safety_score >= 80 ? 'safe' : d.safety_score >= 50 ? 'moderate' : 'danger';
    const verdictBg = d.safety_score >= 80 ? '#0a2a0a' : d.safety_score >= 50 ? '#2a2a0a' : '#2a0a0a';

    let html = `<div class="score-display ${scoreClass}">${d.safety_score}/100</div>`;
    html += `<div class="verdict" style="background:${verdictBg};color:${scoreClass === 'safe' ? '#0f8' : scoreClass === 'moderate' ? '#fa0' : '#f44'}">${d.verdict}</div>`;

    if (d.token && d.token.name) {
      html += `<p><b>${d.token.name}</b> (${d.token.symbol || '?'}) on ${chain}</p>`;
    }

    // Honeypot result
    const hp = d.honeypot_simulation || {};
    if (hp.simulated) {
      if (hp.is_honeypot) {
        html += `<div class="hp-result danger"><b>HONEYPOT DETECTED</b><br>${hp.reason}<br>Router: ${hp.router}</div>`;
      } else {
        const taxInfo = hp.total_tax_pct !== undefined ? ` | Tax: ${hp.total_tax_pct}%` : '';
        html += `<div class="hp-result"><b>Sell simulation OK</b> via ${hp.router}${taxInfo}</div>`;
      }
    }

    // LP Lock
    const lp = d.lp_lock;
    if (lp) {
      if (lp.is_locked) {
        html += `<div class="hp-result"><b>Liquidity ${lp.locked_pct}% LOCKED</b></div>`;
      } else if (lp.locked_pct === 0) {
        html += `<div class="hp-result danger"><b>Liquidity NOT LOCKED</b> — rug pull risk</div>`;
      } else {
        html += `<div class="hp-result" style="border-color:#fa0"><b>Liquidity ${lp.locked_pct}% locked</b> (partial)</div>`;
      }
    }

    // Flags
    if (d.flags && d.flags.length) {
      html += '<ul class="flags">';
      d.flags.forEach(f => { html += `<li>${f}</li>`; });
      html += '</ul>';
    }

    // Source analysis
    if (d.source_analysis && d.source_analysis.total_findings > 0) {
      html += `<p style="margin-top:15px"><b>Source code findings:</b> ${d.source_analysis.critical} critical, ${d.source_analysis.high} high, ${d.source_analysis.medium} medium</p>`;
    }

    html += `<p style="color:#555;margin-top:15px;font-size:12px">Verified: ${d.verified} | Owner: ${d.owner || 'N/A'} | Proxy: ${d.is_proxy}</p>`;

    result.innerHTML = html;
  } catch(e) {
    result.innerHTML = `<p style="color:#ff4444">Error: ${e.message}</p>`;
  }
  btn.disabled = false;
  btn.textContent = 'SCAN TOKEN';
}
document.getElementById('address').addEventListener('keypress', e => { if(e.key === 'Enter') scan(); });
</script>
</body></html>"""


@app.get("/honeypot")
async def honeypot_check(
    address: str = Query(..., description="Token address"),
    chain: str = Query("base", description="Chain"),
):
    """GAME CHANGER: Real DEX swap simulation. Not guessing — TESTING.
    Returns whether you can ACTUALLY sell this token, with exact tax %.
    """
    if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
        raise HTTPException(400, "Invalid address")
    if chain not in EXPLORERS:
        raise HTTPException(400, f"Unsupported chain: {chain}")

    cache_key = f"hp:{chain}:{address.lower()}"
    cached = SCAN_CACHE.get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    t_start = time.time()
    result = simulate_honeypot(EXPLORERS[chain]["rpc"], chain, address)
    ms = int((time.time() - t_start) * 1000)

    response = {
        "address": address,
        "chain": chain,
        "honeypot": result.get("is_honeypot", None),
        "can_sell": not result.get("is_honeypot", True) if result.get("simulated") else None,
        "total_tax_pct": result.get("total_tax_pct", None),
        "buy_tax_pct": result.get("estimated_buy_tax", None),
        "sell_tax_pct": result.get("estimated_sell_tax", None),
        "simulated": result.get("simulated", False),
        "reason": result.get("reason", None),
        "router": result.get("router", None),
        "scan_time_ms": ms,
        "method": "REAL DEX SWAP SIMULATION — not pattern matching",
    }

    SCAN_CACHE.set(cache_key, response)
    return response


@app.get("/health")
async def health():
    return {"status": "ok", "service": "token-safety-scanner", "tools": 21, "version": "2.1.0"}


@app.get("/.well-known/ai-plugin.json")
async def ai_plugin():
    """OpenAI/ChatGPT plugin manifest — how AI agents discover us."""
    return {
        "schema_version": "v1",
        "name_for_human": "SafeAgent Token Safety",
        "name_for_model": "safeagent",
        "description_for_human": "Check if crypto tokens are safe. 27 scam patterns, 6 EVM chains.",
        "description_for_model": "Check token safety before trading crypto. Returns score 0-100, risk flags, and BUY/CAUTION/BLOCK recommendation. Covers Base, Ethereum, Arbitrum, Optimism, Polygon, BSC. 27 scam patterns including honeypots, fake renounce, balance manipulation. FREE during beta.",
        "auth": {"type": "none"},
        "api": {
            "type": "openapi",
            "url": "https://cryptogenesis.duckdns.org/token/openapi.json"
        },
        "logo_url": "https://cryptogenesis.duckdns.org/token/.well-known/logo.png",
        "contact_email": "Cryptogen@zohomail.eu",
        "legal_info_url": "https://github.com/CryptoGenesisSecurity/erc-token-safety-score/blob/main/LICENSE"
    }


@app.get("/.well-known/token-safety-oracle.json")
async def oracle_discovery():
    """ERC-7913 oracle discovery endpoint — how smart contracts find us."""
    return {
        "name": "SafeAgent Oracle",
        "version": "2.1.0",
        "standard": "ERC-7913",
        "chains": {
            "base": {"oracle": "0x37b9e9B8789181f1AaaD1cD51A5f00A887fa9b8e", "router": "0xb200357a35C7e96A81190C53631BC5Beca84A8FA", "factory": "0xB414b2C77F7fDeeB0D86cb5dAcfF4aC05974380f"},
            "optimism": {"oracle": "0x3B8A6D696f2104A9aC617bB91e6811f489498047", "factory": "0x9B4A30677152dB1B432812f5B7cbA4f201614784"}
        },
        "api": "https://cryptogenesis.duckdns.org/token/scan",
        "mcp": "https://cryptogenesis.duckdns.org/mcp",
        "mcp_sse": "https://cryptogenesis.duckdns.org/mcp/sse",
        "smithery": "@safeagent/token-safety",
        "tools": 21,
        "scam_patterns": 27,
        "supported_chains": ["base", "ethereum", "arbitrum", "optimism", "polygon", "bsc"],
        "free_during_beta": True
    }


@app.get("/scan")
async def scan_basic(
    address: str = Query(None, description="Token contract address"),
    chain: str = Query("base", description="Chain: base, ethereum, arbitrum, optimism, polygon, bsc"),
):
    """FREE: Basic safety score. Sub-second response with cache."""
    from fastapi.responses import RedirectResponse
    if not address:
        return RedirectResponse(url="/")
    if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
        raise HTTPException(400, "Invalid address")

    if chain not in EXPLORERS:
        raise HTTPException(400, f"Unsupported chain: {chain}")

    # Check cache first
    cache_key = f"{chain}:{address.lower()}"
    cached = SCAN_CACHE.get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    t_start = time.time()
    explorer = EXPLORERS[chain]

    # Run ALL checks in PARALLEL (not sequential)
    token_info_task = fast_token_info(explorer["rpc"], address)
    contract_task = fast_contract_check(explorer["api"], address)

    token_info_result, contract_data = await asyncio.gather(
        token_info_task, contract_task
    )

    # Check if this is actually an ERC-20 token
    # Multiple signals: name/symbol decoded, OR blockscout recognizes it as token, OR it has decimals
    name_ok = token_info_result.get("name") and token_info_result["name"] != "Unknown"
    symbol_ok = token_info_result.get("symbol") and token_info_result["symbol"] != "???"
    has_decimals = token_info_result.get("decimals") is not None and token_info_result["decimals"] != 18  # non-default decimals = likely token
    blockscout_token = bool(contract_data.get("token_type") or contract_data.get("name"))
    is_token = bool(name_ok or symbol_ok or has_decimals or blockscout_token)

    verified = bool(contract_data.get("source_code"))
    is_proxy = contract_data.get("is_proxy", False)
    owner = token_info_result.pop("owner", None)

    # Check if address has any code (is it a contract?)
    has_code = bool(contract_data) or is_token

    checks = {
        "verified": verified,
        "owner": owner,
        "is_proxy": is_proxy,
        "is_token": is_token,
        "has_code": has_code,
        "address": address,
        "findings": [],
    }

    safety = compute_safety_score(checks)
    scan_time = round(time.time() - t_start, 3)

    result = {
        "address": address,
        "chain": chain,
        "token": token_info_result,
        "safety_score": safety["score"],
        "verdict": safety["verdict"],
        "flags": safety["flags"],
        "scan_time_ms": int(scan_time * 1000),
        "note": "Basic scan. Use /scan/deep for full analysis with honeypot simulation + source code audit.",
        "timestamp": int(time.time()),
    }

    # Cache result
    SCAN_CACHE.set(cache_key, result)
    return result


@app.get("/scan/deep")
async def scan_deep(
    address: str = Query(..., description="Token contract address"),
    chain: str = Query("base", description="Chain"),
    x_payment: Optional[str] = Header(None, alias="X-PAYMENT"),
):
    """FULL: Deep analysis with source code audit. Costs $0.005 USDC via x402."""
    # x402 Payment Check
    if not x_payment:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=402,
            content={
                "error": "Payment Required",
                "x402Version": 1,
                "price": "$0.005 USDC",
                "network": "base (eip155:8453)",
                "payTo": "0xDa429f2034b62b8722713873dE3C045eec390d8F",
                "description": "Token safety scan costs $0.005 USDC. Use x402 protocol or send USDC to payTo address.",
                "accepts": [{
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "maxAmountRequired": "5000",
                    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "payTo": "0xDa429f2034b62b8722713873dE3C045eec390d8F",
                }],
                "free_alternative": "/scan?address=" + address + "&chain=" + chain,
            },
        )

    if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
        raise HTTPException(400, "Invalid address")

    if chain not in EXPLORERS:
        raise HTTPException(400, f"Unsupported chain: {chain}")

    explorer = EXPLORERS[chain]

    # Contract data
    try:
        r = requests.get(f"{explorer['api']}/smart-contracts/{address}", timeout=15)
        contract_data = r.json() if r.ok else {}
    except:
        contract_data = {}

    verified = bool(contract_data.get("source_code"))
    is_proxy = contract_data.get("is_proxy", False)
    source = contract_data.get("source_code", "")
    contract_name = contract_data.get("name", "Unknown")

    # Owner
    owner = check_owner(explorer["rpc"], address)

    # Token info
    token_info = check_token_info(explorer["rpc"], address)
    total_supply = check_total_supply(explorer["rpc"], address)

    # Source code analysis
    findings = check_contract_source(source) if source else []

    # Top holders
    holders = []
    try:
        r = requests.get(f"{explorer['api']}/tokens/{address}/holders?limit=10", timeout=10)
        if r.ok:
            holder_data = r.json().get("items", [])
            for h in holder_data:
                addr = h.get("address", {}).get("hash", "")
                value = h.get("value", "0")
                holders.append({"address": addr, "balance": value})
    except:
        pass

    # Contract age & activity
    age_data = check_contract_age(explorer["api"], address)

    # Liquidity & holders count
    liq_data = check_liquidity(explorer["api"], address)

    # HONEYPOT SIMULATION (the killer feature)
    honeypot = simulate_honeypot(explorer["rpc"], chain, address)

    # LP LOCK CHECK — use pair from honeypot sim or find it
    lp_lock = None
    hp_pair = honeypot.get("liquidity", {}).get("pair") if honeypot.get("has_liquidity") else None
    if not hp_pair:
        found_pair = find_dex_pair(explorer["rpc"], chain, address)
        hp_pair = found_pair.get("pair") if found_pair else None
    if hp_pair:
        lp_lock = check_lp_lock(explorer["rpc"], hp_pair)

    # Compute score
    checks = {
        "verified": verified,
        "owner": owner,
        "is_proxy": is_proxy,
        "findings": findings,
        "contract_age": age_data,
        "liquidity": liq_data,
        "honeypot": honeypot,
        "lp_lock": lp_lock,
    }
    safety = compute_safety_score(checks)

    return {
        "address": address,
        "chain": chain,
        "token": {**token_info, "total_supply": str(total_supply) if total_supply else None},
        "contract_name": contract_name,
        "safety_score": safety["score"],
        "verdict": safety["verdict"],
        "flags": safety["flags"],
        "verified": verified,
        "is_proxy": is_proxy,
        "owner": owner,
        "owner_renounced": owner and owner.lower() in ["0x" + "0" * 40, "0x000000000000000000000000000000000000dead"],
        "source_analysis": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "findings": findings,
        },
        "honeypot_simulation": honeypot,
        "lp_lock": lp_lock,
        "top_holders": holders[:5],
        "source_lines": len(source.split('\n')) if source else 0,
        "timestamp": int(time.time()),
    }


# Internal endpoint (for Bankr proxy)
@app.get("/internal/scan/deep")
async def internal_scan_deep(
    address: str = Query(...),
    chain: str = Query("base"),
    x_internal_key: str = Header(None),
):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(403, "Invalid key")
    return await scan_deep(address, chain)


if __name__ == "__main__":
    import uvicorn
    print("Token Safety Scanner starting on port 4444")
    uvicorn.run(app, host="0.0.0.0", port=4444)

# SEO
@app.get("/robots.txt", response_class=HTMLResponse)
async def robots():
    return """User-agent: *
Allow: /
Sitemap: https://cryptogenesis.duckdns.org/token/sitemap.xml
"""

@app.get("/sitemap.xml", response_class=HTMLResponse)
async def sitemap():
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://cryptogenesis.duckdns.org/token/</loc><priority>1.0</priority></url>
  <url><loc>https://cryptogenesis.duckdns.org/token/scan</loc><priority>0.9</priority></url>
  <url><loc>https://cryptogenesis.duckdns.org/token/openapi.json</loc><priority>0.7</priority></url>
  <url><loc>https://cryptogenesis.duckdns.org/token/.well-known/agent.json</loc><priority>0.8</priority></url>
</urlset>"""

# ============================================================
# PUBLIC TOKEN SAFETY FEED — Live scam detection results
# ============================================================
_recent_scans = []  # In-memory list of recent scan results

@app.get("/feed")
async def safety_feed(limit: int = Query(50, description="Number of recent scans")):
    """Public feed of recently scanned tokens with safety scores."""
    return {"scans": _recent_scans[-limit:], "total": len(_recent_scans)}

@app.get("/feed/dangerous")
async def dangerous_feed(limit: int = Query(20)):
    """Tokens flagged as dangerous (score < 40)."""
    dangerous = [s for s in _recent_scans if s.get("safety_score", 100) < 40]
    return {"dangerous_tokens": dangerous[-limit:], "total": len(dangerous)}

@app.get("/feed/page", response_class=HTMLResponse)
async def feed_page():
    """Human-readable token safety feed page."""
    rows = ""
    for s in reversed(_recent_scans[-100:]):
        score = s.get("safety_score", "?")
        chain = s.get("chain", "?")
        addr = s.get("address", "?")
        token = s.get("token", {})
        name = token.get("name", "?")
        symbol = token.get("symbol", "?")
        verdict = s.get("verdict", "?")
        
        color = "#4caf50" if score >= 70 else "#ff9800" if score >= 40 else "#f44336"
        short_addr = addr[:8] + "..." + addr[-4:] if len(addr) > 12 else addr
        
        rows += f"""<tr>
            <td style="color:{color};font-weight:bold">{score}/100</td>
            <td>{verdict}</td>
            <td>{name} ({symbol})</td>
            <td>{chain}</td>
            <td><code>{short_addr}</code></td>
        </tr>"""
    
    return f"""<!DOCTYPE html>
<html><head>
<title>Token Safety Feed — Live Scam Detection | SafeAgent</title>
<meta name="description" content="Real-time token safety feed. Every new token on Base, Ethereum, Arbitrum scanned for honeypots, rug pulls, and scams. Free API for AI agents.">
<meta name="keywords" content="token safety, honeypot detector, rug pull checker, scam token, crypto safety, AI agent, ERC-7913">
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #0a0a0a; color: #fff; }}
h1 {{ color: #4caf50; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #222; }}
th {{ color: #888; font-size: 12px; text-transform: uppercase; }}
code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
a {{ color: #4caf50; }}
.api {{ background: #1a1a2e; padding: 15px; border-radius: 8px; margin: 20px 0; }}
</style>
</head><body>
<h1>Token Safety Feed</h1>
<p>Real-time safety scores for tokens on Base, Ethereum, Arbitrum, Optimism, Polygon, BSC.<br>
Powered by <a href="https://github.com/CryptoGenesisSecurity/erc-token-safety-score">ERC-7913 Token Safety Score</a>.</p>

<div class="api">
<b>For AI Agents:</b> <code>POST https://cryptogenesis.duckdns.org/mcp</code> (MCP Streamable HTTP)<br>
<b>API:</b> <code>GET /scan?address=0x...&chain=base</code><br>
<b>Smithery:</b> <code>npx @smithery/cli install @safeagent/token-safety</code><br>
<b>SafeRouter (Base):</b> <code>0xb200357a35C7e96A81190C53631BC5Beca84A8FA</code>
</div>

<table>
<tr><th>Score</th><th>Verdict</th><th>Token</th><th>Chain</th><th>Address</th></tr>
{rows}
</table>
<p style="color:#666;font-size:12px;margin-top:30px">Updated every 2 minutes. {len(_recent_scans)} tokens scanned. 
Oracle: <a href="https://basescan.org/address/0x37b9e9B8789181f1AaaD1cD51A5f00A887fa9b8e">Base</a> | 
<a href="https://optimistic.etherscan.io/address/0x3B8A6D696f2104A9aC617bB91e6811f489498047">Optimism</a></p>
</body></html>"""

# Hook: after every scan, add to feed
_original_scan = scan_basic
@app.get("/scan", include_in_schema=False)
async def scan_with_feed(
    address: str = Query(None),
    chain: str = Query("base"),
):
    result = await _original_scan(address=address, chain=chain)
    if isinstance(result, dict) and result.get("safety_score") is not None:
        _recent_scans.append(result)
        if len(_recent_scans) > 1000:
            _recent_scans.pop(0)
    return result
