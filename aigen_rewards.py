"""$AIGEN Token Rewards — Earn tokens by using SafeAgent tools."""
import json, time
from pathlib import Path

LEDGER = Path("/home/luna/crypto-genesis/shield-rewards/ledger.json")

REWARDS = {
    "shield": 10, "test_honeypot": 5, "check_token_safety": 3,
    "execute_safely": 8, "check_approval_safety": 3, "simulate_swap": 5,
    "create_agent_token": 20, "default": 1,
}
FIRST_USE_BONUS = 100

def load():
    if LEDGER.exists():
        return json.loads(LEDGER.read_text())
    return {"agents": {}, "total_distributed": 0, "total_agents": 0}

def save(ledger):
    LEDGER.write_text(json.dumps(ledger, indent=2))

def reward(agent_id, action):
    ledger = load()
    tokens = REWARDS.get(action, REWARDS["default"])
    is_new = agent_id not in ledger["agents"]

    if is_new:
        ledger["agents"][agent_id] = {"balance": 0, "total_earned": 0, "actions": 0, "first_seen": int(time.time())}
        ledger["total_agents"] += 1
        tokens += FIRST_USE_BONUS

    a = ledger["agents"][agent_id]
    a["balance"] += tokens
    a["total_earned"] += tokens
    a["actions"] += 1
    a["last_seen"] = int(time.time())
    ledger["total_distributed"] += tokens
    save(ledger)

    return {"earned": tokens, "balance": a["balance"], "total": a["total_earned"], "new": is_new}

def leaderboard(n=10):
    ledger = load()
    top = sorted(ledger["agents"].items(), key=lambda x: -x[1]["total_earned"])[:n]
    return {"top": [{"id": a[:12], "earned": d["total_earned"]} for a, d in top],
            "agents": ledger["total_agents"], "distributed": ledger["total_distributed"]}
