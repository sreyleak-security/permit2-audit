"""
permit2_audit.py - read-only Permit2 allowance + EIP-7702 delegation audit.
Usage: python permit2_audit.py 0xYourAddress [--rpc https://your.node]
Deps: pip install requests

Author: Srey Leak. MIT License. Educational content, not security advice.
"""
import argparse
import requests

PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

rpc_id = 0


def rpc(url, method, params):
    global rpc_id
    rpc_id += 1
    r = requests.post(url, json={"jsonrpc": "2.0", "id": rpc_id,
                                 "method": method, "params": params}, timeout=30)
    r.raise_for_status()
    out = r.json()
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def check_delegation(rpc_url, addr):
    """EIP-7702: an EOA under delegation has runtime code starting 0xef01."""
    code = rpc(rpc_url, "eth_getCode", [addr, "latest"])
    if code in ("0x", "", None):
        print("[OK]   no EIP-7702 delegation (EOA has no code)")
    else:
        prefix = code[:10]
        marker = "DELEGATED" if prefix.startswith("0xef01") else "HAS-CODE"
        print(f"[!!]   {marker}: code prefix {prefix}, size {len(code) // 2 - 1} bytes")
        print("       -> inspect the delegation target NOW if you did not set this up")


def permit2_allowances(rpc_url, addr, from_block="0x0", max_logs=200):
    """Enumerate (token, spender) pairs from Permit2 Approval events."""
    pad = "0" * 24
    params = {
        "fromBlock": from_block, "toBlock": "latest",
        "address": PERMIT2,
        "topics": [APPROVAL_TOPIC, None,
                   "0x" + pad + addr.lower().removeprefix("0x")],
    }
    logs = rpc(rpc_url, "eth_getLogs", [params])[-max_logs:]
    print(f"[i]    {len(logs)} Permit2 Approval events found")
    seen = {}
    for log in logs:
        token = log["address"]
        spender = "0x" + log["topics"][2][-40:]
        seen[(token.lower(), spender.lower())] = int(log["blockNumber"], 16)
    for (token, spender), block in sorted(seen.items(), key=lambda kv: -kv[1]):
        print(f"       token {token} -> spender {spender} (last write at block {block})")
    print("[i]    re-read current amounts via eth_call to Permit2.allowance()")
    print("       near-unlimited + unused = revoke candidate")


def main():
    ap = argparse.ArgumentParser(description="Read-only Permit2 + EIP-7702 wallet audit")
    ap.add_argument("address")
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--from-block", default="0x0")
    a = ap.parse_args()
    addr = a.address if a.address.startswith("0x") else "0x" + a.address
    print(f"Auditing {addr}")
    check_delegation(a.rpc, addr)
    permit2_allowances(a.rpc, addr, a.from_block)


if __name__ == "__main__":
    main()
