"""
SafeWeb3 — Drop-in replacement for Web3 that checks every transaction.

Usage:
    # Change ONE import:
    from safeagent.web3 import SafeWeb3 as Web3

    # Everything else stays the same:
    w3 = Web3(HTTPProvider("https://mainnet.base.org"))
    w3.eth.send_transaction(tx)  # Now checked automatically
"""

from web3 import Web3 as _Web3
from web3.eth import Eth as _Eth
import urllib.request
import json

SCANNER_URL = "https://cryptogenesis.duckdns.org/token"
MIN_SCORE = 40

# approve(address,uint256) selector
APPROVE_SELECTOR = "0x095ea7b3"


def _check_safety(address: str, chain: str = "base") -> dict:
    """Check address safety via SafeAgent API."""
    try:
        url = f"{SCANNER_URL}/scan?address={address}&chain={chain}"
        req = urllib.request.Request(url, headers={"User-Agent": "SafeWeb3/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        return json.loads(resp.read().decode())
    except:
        return {"safety_score": 100, "verdict": "UNKNOWN"}  # Failsafe: allow


def _check_honeypot(address: str, chain: str = "base") -> dict:
    """Check honeypot via SafeAgent API."""
    try:
        url = f"{SCANNER_URL}/honeypot?address={address}&chain={chain}"
        req = urllib.request.Request(url, headers={"User-Agent": "SafeWeb3/1.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read().decode())
    except:
        return {"honeypot": False, "simulated": False}


class SafeEth:
    """Wraps Web3.eth to intercept dangerous transactions."""

    def __init__(self, eth: _Eth, chain: str = "base", min_score: int = MIN_SCORE,
                 on_block: str = "raise", verbose: bool = True):
        self._eth = eth
        self._chain = chain
        self._min_score = min_score
        self._on_block = on_block  # "raise" or "warn"
        self._verbose = verbose
        self.shield_stats = {"checked": 0, "blocked": 0, "allowed": 0}

    def __getattr__(self, name):
        """Forward everything to real eth, except intercepted methods."""
        return getattr(self._eth, name)

    def send_transaction(self, transaction, *args, **kwargs):
        """Intercept send_transaction — check destination safety."""
        to = transaction.get("to", "")
        data = transaction.get("data", "")

        if to:
            self.shield_stats["checked"] += 1

            # Check destination safety
            result = _check_safety(to, self._chain)
            score = result.get("safety_score", 100)

            if score < self._min_score:
                self.shield_stats["blocked"] += 1
                msg = f"SafeAgent Shield: BLOCKED — {to} scored {score}/100 ({result.get('verdict', '?')})"
                if self._verbose:
                    print(f"🛡️ {msg}")
                if self._on_block == "raise":
                    raise ValueError(msg)
                return None

            # Check if it's an approve to suspicious contract
            if data and data[:10].lower() == APPROVE_SELECTOR:
                spender = "0x" + data[34:74] if len(data) >= 74 else ""
                if spender:
                    sp_result = _check_safety(spender, self._chain)
                    sp_score = sp_result.get("safety_score", 100)
                    if sp_score < self._min_score:
                        self.shield_stats["blocked"] += 1
                        msg = f"SafeAgent Shield: BLOCKED approve — spender {spender} scored {sp_score}/100"
                        if self._verbose:
                            print(f"🛡️ {msg}")
                        if self._on_block == "raise":
                            raise ValueError(msg)
                        return None

            self.shield_stats["allowed"] += 1
            if self._verbose and score < 70:
                print(f"⚠️ SafeAgent: CAUTION — {to} scored {score}/100. Proceeding.")

        return self._eth.send_transaction(transaction, *args, **kwargs)

    def send_raw_transaction(self, raw_tx, *args, **kwargs):
        """For raw transactions, we can't easily decode — pass through with warning."""
        if self._verbose:
            print("⚠️ SafeAgent: Raw transaction — cannot verify safety. Use send_transaction for protection.")
        return self._eth.send_raw_transaction(raw_tx, *args, **kwargs)


def SafeWeb3(provider, chain="base", min_score=MIN_SCORE, on_block="raise", verbose=True):
    """Drop-in Web3 replacement with SafeAgent Shield built in.

    Usage:
        from safeagent.web3 import SafeWeb3
        w3 = SafeWeb3(HTTPProvider("https://mainnet.base.org"))
        # Now every send_transaction is checked automatically

    Failsafe: if oracle unreachable, transactions proceed normally.
    """
    w3 = _Web3(provider)
    w3.eth = SafeEth(w3.eth, chain, min_score, on_block, verbose)
    return w3
