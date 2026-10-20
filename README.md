# permit2-audit

Read-only wallet audit script: enumerate Permit2 allowances and detect
EIP-7702 delegation on any Ethereum-style address.

Author: Srey Leak — independent wallet-security researcher.
Concepts explained: https://brainresearchhub.net/research/security/eip-7702-vs-permit2-comparison

## Why

Two 2026-era drain vectors live at the approval layer:

- **Permit2** centralizes token approvals in one contract; a single permit
  signature can hand a drainer a near-unlimited, time-boxed allowance.
- **EIP-7702** lets an EOA delegate its code; malicious delegation installs
  sweeper logic at your own address.

Both monetize signatures users have been trained to sign routinely. The
countermeasure is enumeration: know what your address has permitted, and to whom.

## Usage

```
pip install requests
python permit2_audit.py 0xYourAddress --rpc https://your.jsonrpc.endpoint
```

Read-only: two JSON-RPC methods used (`eth_getCode`, `eth_getLogs`), no keys,
no transactions.

## Reading the output

- `eth_getCode` non-empty with a `0xef01` prefix → your EOA is delegating
  somewhere. If that was not you, treat it as an incident.
- Permit2 Approval events → (token, spender) pairs. Re-read current amounts
  via `Permit2.allowance()` before revoking; events show the last write only.
- Near-unlimited allowances to spenders you do not actively use → revoke.

## Files

- `permit2_audit.py` — the audit script (stdlib + requests)
- `LICENSE` — MIT

## Related research

- Permit2 vs EIP-7702 comparison: https://brainresearchhub.net/research/security/eip-7702-vs-permit2-comparison
- Revoking approvals, step by step: https://brainresearchhub.net/research/security/revoke-approvals-guide
- Live sweeper-contract case study (EIP-7702):
  https://brainresearchhub.net/research/security/crimeenjoyor-sweeper-contract-eip-7702
- EIP-7702 CLI checker (companion tool):
  https://brainresearchhub.net/research/security/check-wallet-eip-7702-cli

## Disclaimer

Educational content, not security advice. Read-only, but verify all findings
against official documentation before acting on them.
