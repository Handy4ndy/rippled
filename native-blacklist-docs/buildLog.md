# Build Log — Native Blacklist Provider & Trustee

Date: 2026-04-23

Phase 0 — Setup (completed)

- Branch: `Handy4ndy/native-blacklist-provider-trustee` (pushed to fork `myfork`)
- Commit: "Phase 0: Add blacklist SFields, transaction and ledger-entry macros"
- Files changed:
  - `include/xrpl/protocol/detail/sfields.macro` — added `sfBlacklistAccount`, `sfBlacklisted`, `sfBlacklistFlags`, `sfBlacklistTrustFlags`
  - `include/xrpl/protocol/detail/transactions.macro` — added `ttBLACKLIST_SET` and `ttBLACKLIST_TRUST` transaction entries and includes for transactor headers; both entries set to `Delegation::notDelegable`
  - `include/xrpl/protocol/detail/ledger_entries.macro` — added `ltBLACKLIST_ENTRY` and `ltBLACKLIST_TRUST` ledger-entry templates

Notes:
- These macro edits update the protocol autogen sources; a full CMake build is required next to regenerate headers under `include/xrpl/protocol_autogen/` and compile.
- Next planned steps: add `keylet` helpers in `src/libxrpl/protocol/Indexes.cpp`, implement transactor skeletons for `BlacklistSet` and `BlacklistTrustSet`, and run a local build to validate autogen and compilation.
- Documentation update: `native-blacklist-docs/XLS-110-Blacklist.md` and `native-blacklist-docs/scope.md` updated to require gating via a protocol amendment and propose `featureNativeBlacklist` as a placeholder feature constant.
