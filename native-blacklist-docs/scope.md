# Build Scope — Native Blacklist Provider & Trustee

This document contains the implementation plan and phased build scope for a reference Rippled (xrpld) fork that adds native Blacklist Provider / Trustee support.

## Overview

The work implements two new transaction types (`BlacklistSet`, `BlacklistTrustSet`) and two new ledger-entry types (`BlacklistEntry`, `BlacklistTrust`) and enforces blacklist checks during payment application for opt-in Trustee accounts.

## Phases

### Phase 0: Setup (1 day) (Completed / Pushed to fork / build log updated)
- Fork latest XRPLF/rippled (main or develop).
- Create a branch `feature/native-blacklist-provider-trustee`.
- Add new transaction type IDs in `src/xrpl/protocol/TxTypes.h` (pick unused values, e.g. `ttBLACKLIST_SET`, `ttBLACKLIST_TRUST_SET`).
- Add ledger entry type constants and SField definitions.
\
Note: these transactions are security-sensitive and should be gated by an amendment. Add a placeholder feature constant (e.g. `featureNativeBlacklist`) and reference it in `transactions.macro` (replace `uint256{}`) so the transactions are disabled until the amendment is enabled.

### Phase 1: Ledger Objects & Serialization (2–3 days)
- Implement `BlacklistEntry` and `BlacklistTrust` ledger formats in `src/xrpl/protocol/impl/LedgerFormats.cpp` and related headers.
- Add serialization, SHAMap hashing and directory linking (reuse OwnerNode patterns).
- Ensure canonical JSON and protocol fields are registered.

### Phase 2: Transaction Handlers (3–5 days)
- Add transaction handlers mirroring `DepositPreauth` (e.g. `src/xrpld/app/tx/detail/BlacklistSet.cpp`, `BlacklistTrustSet.cpp`).
- Implement preclaim, `doApply`, fee calculation, and owner-only enforcement for provider operations.
- Create/delete ledger objects and maintain owner directories.

### Phase 3: Enforcement Logic (2–4 days)
- Add enforcement helper `isBlacklisted(ApplyContext&, AccountID source, AccountID dest)`.
- Integrate check into `Payment` (and optionally other fund-moving txs) in preclaim/apply so a matching `BlacklistEntry` yields `tecBLACKLISTED`.
- Add `tecBLACKLISTED` to `src/xrpl/protocol/TER.h`.

### Phase 4: RPC & Tooling (2 days)
- Add `blacklist_authorized` RPC (mirrors `deposit_authorized`).
- Extend `account_info`/ledger calls to return blacklist trust and entries when requested.

### Phase 5: Testing & Demo Network (3–5 days)
- Unit tests for new transactions and enforcement helper.
- Integration test: 3-node testnet demonstrating Provider, Trustee, blacklist entry creation, and a failing `Payment` to a trusting Trustee.
- Docker / startup scripts to spin up the demo network.

### Phase 6: Polish & Sharing (1–2 days)
- Update `server_definitions` detection for client libraries.
- Add example JSON transactions, docs, and README for running the fork.

## Deliverables
- `scope.md` — this file (implementation phases and file-level targets).
- `XLS-110-Blacklist.md` — protocol proposal and specification (separate file).
- Reference implementation branch `feature/native-blacklist-provider-trustee`.

## Effort Estimate
Total: ~2–4 weeks for one experienced XRPL C++ developer (parallelization can shorten calendar time).

## Expanded Implementation Scope — File-level Deliverables

This section maps the high-level phases to explicit files, helpers, and tests to change or add.

- Protocol registration and fields
	- Update `src/xrpl/protocol/detail/transactions.macro` to add `BlacklistSet` and `BlacklistTrustSet` entries.
	- Update `src/xrpl/protocol/detail/ledger_entries.macro` to add `ltBLACKLIST_ENTRY` and `ltBLACKLIST_TRUST`.
	- Add SField definitions (e.g. `sfBlacklistAccount`, `sfBlacklistFlags`, `sfProvider`, `sfBlacklistTrustFlags`, `sfBlacklisted`) in `include/xrpl/protocol/SField.*`.

- Index/keylet helpers
	- Add `keylet::blacklistEntry(provider, blacklisted)` and `keylet::blacklistTrust(owner, provider)` prototypes in `include/xrpl/protocol/Indexes.h` and implement in `src/libxrpl/protocol/Indexes.cpp` following existing patterns (SHA-512Half or `keylet` helpers).

- Ledger entry formats & autogen
	- Ensure ledger entry SOTemplates are registered so generated wrappers appear under `include/xrpl/protocol_autogen/ledger_entries/`.

- Transaction handlers
	- New transactors: `src/libxrpl/tx/transactors/blacklist/BlacklistSet.cpp` and `BlacklistTrustSet.cpp` with headers in `include/xrpl/tx/transactors/...`, modeled on `DepositPreauth.cpp`.
	- Register formats so `TxFormats` and `LedgerFormats` include the new types.

- Enforcement helper and integration
	- Implement `isBlacklisted(ReadView/ApplyView&, AccountID const& source, AccountID const& dest)` (e.g., `src/libxrpl/tx/transactors/BlacklistCheck.cpp`) using `DirectoryHelpers::forEachItem` and `keylet::blacklistEntry` lookups.
	- Call `isBlacklisted` from `src/libxrpl/tx/transactors/payment/Payment.cpp` in `preclaim` and/or `doApply` to return `tecBLACKLISTED` when applicable.
	- Add `tecBLACKLISTED` to `include/xrpl/protocol/TER.h`.

- Ledger directory handling & reserves
	- Use `view().dirInsert`, `sfOwnerNode`, and `adjustOwnerCount` patterns (see `DepositPreauth::doApply`) when creating/deleting `BlacklistTrust` and `BlacklistEntry` SLEs to account for reserve changes.

- RPC and tools
	- Create `src/xrpld/rpc/handlers/blacklist/BlacklistAuthorized.cpp` mirroring `deposit_authorized` and register it in RPC handlers.
	- Extend `src/xrpld/rpc/handlers/account/AccountInfo.cpp` or `injectSLE` behavior to include blacklist trust/entries when requested.

- Tests & CI
	- Unit tests for new transactors and `isBlacklisted` under `src/test` (or `src/test/jtx` patterns).
	- Integration test: 3-node testnet demonstrating Provider, Trustee, blacklist entry creation, and a failing `Payment` to a trusting Trustee.
	- Add Docker/dev scripts for demo network and update CI/test manifests if necessary.

- Documentation
	- Finalize `native-blacklist-docs/XLS-110-Blacklist.md` and `scope.md` (this file).
	- Add `native-blacklist-docs/README.md` with build/run/test instructions.

## Notes & Implications from Code Review

- The repository uses macro tables (`transactions.macro`, `ledger_entries.macro`) to generate protocol types and auto-generated headers under `include/xrpl/protocol_autogen/` — update these carefully.
- Keylet/index conventions must be followed (use `keylet::` helpers and canonical index calculations) to ensure correct O(1) lookup behavior and directory layout.
- Reuse `DepositPreauth` patterns for owner-directory insertion/removal and reserve/account owner count adjustments to avoid ledger invariants.
- Adding `tecBLACKLISTED` requires updating `TER.h` and may require client libraries and RPC consumers to handle the new code gracefully.
- Enforcement should be minimal-cost: perform checks only when destination owns `BlacklistTrust` objects.

## Next Steps (recommended)

1. Create `feature/native-blacklist-provider-trustee` branch and commit documentation changes.
2. Implement preparatory changes (macro tables and SField additions, `keylet` helpers, ledger templates) — low-risk and easy to unit test.
3. Implement `BlacklistSet` / `BlacklistTrustSet` transactors and unit tests.
4. Add `isBlacklisted` helper and integrate it into `Payment` transactor; add `tecBLACKLISTED` and tests.
5. Add RPC handler(s) and update `account_info`/tools.
6. Run integration testnet and refine.

If you want, I can start on step 1 and 2 now and push preparatory commits to a new branch.

## Low-level Findings (concrete)

Add these concrete items to the implementation backlog so engineers know exactly what to change and where.

- SFields to add (file: `include/xrpl/protocol/detail/sfields.macro`)
	- `sfProvider` (if missing) — `SF_ACCOUNT`
	- `sfBlacklisted` / `sfBlacklistAccount` — `SF_ACCOUNT`
	- `sfBlacklistFlags` / `sfBlacklistTrustFlags` — `SF_UINT32`

- Macro entries to add
	- `include/xrpl/protocol/detail/transactions.macro`: add `TRANSACTION` entries for `ttBLACKLIST_SET` and `ttBLACKLIST_TRUST` with header includes (`src/libxrpl/tx/transactors/blacklist/BlacklistSet.h`, etc.).
	- `include/xrpl/protocol/detail/ledger_entries.macro`: add `LEDGER_ENTRY` entries for `ltBLACKLIST_ENTRY` and `ltBLACKLIST_TRUST` with SOTemplate fields listed below.

- LedgerNameSpace & keylets (file: `src/libxrpl/protocol/Indexes.cpp` / `include/xrpl/protocol/Indexes.h`)
	- Reserve two unused `LedgerNameSpace` chars (e.g., 'b' / 'B' or unused), add enum entries `BLACKLIST_ENTRY` and `BLACKLIST_TRUST`.
	- Implement `keylet::blacklistEntry(provider, blacklisted)` and `keylet::blacklistTrust(owner, provider)` returning `{lt..., indexHash(..., ...)}`.

- Ledger SOTemplates (macro fields)
	- `BlacklistEntry` fields: `sfProvider`, `sfBlacklisted`, `sfOwnerNode`, `sfPreviousTxnID`, `sfPreviousTxnLgrSeq`, `sfFlags`.
	- `BlacklistTrust` fields: `sfAccount`/`sfOwner`, `sfProvider`, `sfOwnerNode`, `sfPreviousTxnID`, `sfPreviousTxnLgrSeq`, `sfFlags`.

- Transactor files to add (mirror `DepositPreauth` patterns)
	- `include/xrpl/tx/transactors/blacklist/BlacklistSet.h` and `src/libxrpl/tx/transactors/blacklist/BlacklistSet.cpp`
	- `include/xrpl/tx/transactors/blacklist/BlacklistTrustSet.h` and `src/libxrpl/tx/transactors/blacklist/BlacklistTrustSet.cpp`
	- `src/libxrpl/tx/transactors/blacklist/BlacklistCheck.cpp` containing `isBlacklisted` helper.

- Integration points
	- Call `isBlacklisted` in `src/libxrpl/tx/transactors/payment/Payment.cpp` (after destination lookups in `preclaim`/`doApply`).
	- Add `tecBLACKLISTED` to `include/xrpl/protocol/TER.h`.

- Directory & reserve handling (follow `DepositPreauth::doApply`)
	- Use `view().dirInsert(keylet::ownerDir(owner), keylet, describeOwnerDir(owner))` and set `sfOwnerNode`.
	- On deletion, use the same helper to remove ledger entry and call `adjustOwnerCount`.

- RPC & tests
	- Add `src/xrpld/rpc/handlers/blacklist/BlacklistAuthorized.cpp` mirroring `deposit_authorized`.
	- Add unit tests under `src/tests` and `src/test/jtx` integration scenario (Provider, Trustee, blacklisted account).

- Build/regeneration
	- Modifying macro files will change auto-generated headers under `include/xrpl/protocol_autogen/`; run a full CMake build to regenerate and compile.

These low-level items should be added to the workplan and implemented in small, testable commits: (1) macros & SFields, (2) keylets & namespace, (3) transactor skeletons, (4) enforcement helper + Payment integration, (5) RPC + tests.

