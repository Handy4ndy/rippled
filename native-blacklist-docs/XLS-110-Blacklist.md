# XLS-110: Native On-Ledger Blacklist Provider & Trustee Framework

**Status:** Draft

**Authors:** (TBD)

**Date:** April 2026

## Abstract

Introduce two new transaction types (`BlacklistSet`, `BlacklistTrustSet`) and two ledger-entry types (`BlacklistEntry`, `BlacklistTrust`) to supply a native Provider/Trustee blacklist pattern. This mirrors the Xahau Hooks Provider/Trustee behavior but as a deterministic, consensus-level feature in xrpld.

## Activation and Amendments

Both the `BlacklistSet` and `BlacklistTrustSet` transactions (and their ledger-object types) are security-sensitive and must be gated behind a protocol amendment when deployed to the network. For implementation and rollout we intend to add a placeholder feature flag named `featureNativeBlacklist` (final name subject to review). Until that amendment is enabled network-wide, nodes should reject these transactions. In the codebase, the `transactions.macro` entries for these transactions should reference the feature constant (rather than `uint256{}`) so that feature checks and `Permission::isDelegable` observe the amendment state.

## Motivation

- Provide exchanges, bridges, and custodians a fast, opt-in, on-ledger mechanism to reject funds originating from accounts flagged by trusted Providers.
- Avoid reliance on Hooks or external off-ledger tooling; make enforcement native and consensus-deterministic.
- Preserve opt-in nature: non-participating accounts unchanged; blacklisted accounts can still broadcast transactions, but they fail only when hitting a trusting Trustee.

## Specification

1) Transaction Types

- `BlacklistSet` (Provider-side)
	- Issued by a Provider account.
	- Fields: `BlacklistAccount` (AccountID), `BlacklistFlags` (Add/Remove).
	- Effect: Create or delete a `BlacklistEntry` ledger object. Owner-only.

- `BlacklistTrustSet` (Trustee-side)
	- Issued by a Trustee account.
	- Fields: `Provider` (AccountID), `BlacklistTrustFlags` (Trust/Untrust).
	- Effect: Create or delete a `BlacklistTrust` ledger object owned by the Trustee.

2) Ledger Entry Types

- `BlacklistEntry`
	- Fields: `Provider` (AccountID), `Blacklisted` (AccountID), `Flags`, `LedgerIndex` (SHA-512Half(Provider + Blacklisted)).
	- One entry per (Provider, Blacklisted) pair.

- `BlacklistTrust`
	- Fields: `Owner` (Trustee AccountID), `Provider` (AccountID), `Flags`, index hash(Owner + Provider).
	- Multiple allowed per Owner.

3) Enforcement

- On fund-moving transactions (starting with `Payment`):
	- Gather `BlacklistTrust` objects owned by the destination account.
	- For each trusted Provider, compute the `BlacklistEntry` index for (Provider, source account).
	- If an entry exists, fail the transaction with `tecBLACKLISTED` and rollback.

## Error Codes

- `tecBLACKLISTED` — transaction rejected because the source is blacklisted by a Provider trusted by the destination.

## Rationale

- Keeps semantics separate from `DepositPreauth` and `DepositAuth`.
- Mirrors a proven Provider/Trustee pattern from Hooks while being deterministic and cheaper (no runtime Hook execution).

## Security & Incentives

- Providers must secure keys; trustees choose providers they trust.
- Fully auditable on-ledger; market-driven reputation for Providers.

## Optional Extensions

- RPC helpers: `blacklist_authorized` (mirror `deposit_authorized`).
- AccountRoot flag `lsfRequireBlacklistCheck` for single-provider shortcut.
- Future credential-based blacklists or integrations with XLS-70 designs.

## Related Documents
- Build scope and implementation plan: `scope.md`.

