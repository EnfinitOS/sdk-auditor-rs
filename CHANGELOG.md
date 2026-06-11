# Changelog — enfinitos-sdk-auditor (Rust)

All notable changes to the Rust auditor SDK. Tracks the reference
TypeScript implementation (`@enfinitos/sdk-auditor` on npm)
release-for-release with identical wire shapes, reason codes, and
verdicts.

## 0.0.3 — 2026-06-11

### Changed (BREAKING — wire)

- **Settlement line idem key is now content-hash based
  (`settlement.v2`, CRYPTO-01).** `settlement_idem_key` gains a third
  parameter, `ledger_account_code`, and now hashes
  `sha256(meterRecordIdemKey|partyRole|ledgerAccountCode)` instead of
  the 0.0.2 two-field `sha256(meterRecordIdemKey|partyRole)`. Binding
  the ledger account code into the key means two splits for the same
  meter and party role but different ledger accounts no longer collide
  on a single idem key. The bytes fed to sha256 are exactly
  `meter_record_idem_key + "|" + party_role + "|" + ledger_account_code`
  — identical separator, field order, and encoding to the reference
  TypeScript (`settlementIdemKey`) and Python (`settlement_idem_key`)
  ports, so the cross-language parity fixtures stay byte-for-byte
  identical.
- `verify_settlement_reconciliation` reconstructs each line's expected
  idem key with all three fields (the `SettlementLine` already carried
  `ledgerAccountCode` on the wire). The mismatch finding's message is
  now `... does not equal
  sha256(meterIdemKey|partyRole|ledgerAccountCode)`. The
  `SETTLEMENT_IDEM_KEY_MISMATCH` reason code is unchanged.
- `SettlementSummary.schema_version` now also accepts `"settlement.v2"`
  (it remains a free-form `String` field; both `settlement.v1` and
  `settlement.v2` deserialise).
- `SDK_VERSION` constant (stamped onto every audit report) bumped to
  `"0.0.3"`.

### Unchanged

- **Amount, share-sum, and rounding logic are untouched.** The
  `floor(grossCents * share)` recomputation, the per-meter
  share-sum-equals-1.000000 check, and the rounding-tolerance band are
  byte-identical to 0.0.2. This release is the idem-key derivation,
  schema-version acceptance, and version bump only.

### Migration

- Packs must be re-issued by the platform under `settlement.v2` (the
  new 3-field idem keys) to verify VALID. A `settlement.v1` pack whose
  lines carry 2-field idem keys will now report
  `SETTLEMENT_IDEM_KEY_MISMATCH` — by design, since the platform's
  settlement projector moved to the 3-field key. No code change is
  required on the auditor side beyond upgrading the crate.

## 0.0.2 — 2026-06-05

### Added

- **Rights-provenance write-time signature verification** (Wave 14
  Phase 2). New `provenance` module, re-exported at the crate root:
  - `verify_provenance_chain(records, keys, options)` — verifies the
    per-record Ed25519 signatures the platform computes at write time
    on every rights-provenance row (basis assert/verify/reject, right
    issue/suspend/resume/revoke/expire, offer propose/accept/counter/
    reject/withdraw/expire, challenge open/resolve/withdraw). Returns
    a `ProvenanceAuditReport` with the signed/unsigned record
    partition surfaced.
  - `verify_provenance_record(record, index, keys)` — the per-record
    primitive.
  - `canonicalise_provenance_signing_input(fields, key_id)` +
    `PROVENANCE_SIGNING_VERSION` — byte-for-byte reconstruction of
    the platform's flat pipe-delimited signing input
    (`rightProvenance.v1|org|eventType|rightId|basisId|offerId|`
    `beforeHash|afterHash|keyId`, `-` for absent fields).
  - New types: `ProvenanceRecord`, `ProvenanceAuditReport`,
    `ProvenanceSigningFields`, `VerifyProvenanceChainOptions`. Wire
    serialisation uses the same camelCase JSON keys as the TS/Python
    reports.
  - Five new stable reason codes (additive):
    `PROVENANCE_SIGNATURE_INVALID`, `PROVENANCE_SIGNATURE_MALFORMED`,
    `PROVENANCE_CANONICAL_MISMATCH`, `PROVENANCE_UNSIGNED_RECORD`,
    `PROVENANCE_ORG_MISMATCH`; new step kind `provenance_signature`.
- `canonical_json::base64url_decode_strict` — strict RFC 4648 §5
  base64url decoding (rejects whitespace, padding, off-alphabet
  characters, mod-4==1 lengths), parity with the TS reference's
  `base64UrlDecode`. Used by the provenance verifier; the permissive
  `base64url_decode` keeps the pre-0.0.2 receipt path's behaviour.
- **Legacy posture**: records written before write-time provenance
  signing (`signatureAlgorithm: "hmac-sha256"`) report as
  informational SKIPPED steps with reason
  `PROVENANCE_UNSIGNED_RECORD` — never INVALID. Exports produced
  under 0.0.1 keep verifying unchanged; an all-legacy set reports
  SKIPPED (nothing verifiable, nothing failed).

### Changed

- **`SettlementPartyRole` widened from 4 to 8 variants** — added
  `AGENCY`, `AFFILIATE`, `RESELLER`, `TAX_AUTHORITY` to match the
  platform's May-2026 enterprise settlement rebuild
  (counterparty-addressed splits). **Upgrade required for affected
  packs:** unlike the TS/Python ports (whose role types are
  non-enforcing at parse time), the Rust crate's strict serde enum in
  **0.0.1 REJECTED at deserialisation** any pack whose settlement
  lines contained one of the four new roles — `serde_json::from_str`
  failed before any verification ran. 0.0.2 deserialises and verifies
  such packs; every settlement check (idem-key reconstruction, share
  sums, amount recomputation) was already role-agnostic, so verdicts
  on previously-accepted packs are unchanged.
- `SDK_VERSION` constant (stamped onto every audit report) bumped to
  `"0.0.2"`.

### Notes

- No API removals or renames. The provenance verifier is a new,
  parallel primitive; the receipt/chain/metering/settlement pipeline
  is untouched.
- Pair `verify_provenance_chain` (WHO signed each record) with
  `verify_tenant_chain` (each record's POSITION in the tenant's
  append-only history) for the full provenance posture.
- One new (already-present transitively) dependency surface:
  `chrono` parses `occurredAt` for key-validity checks — same crate
  the key directory already used.

## 0.0.1 — 2026-06-03

Initial public release on crates.io.

- `Auditor` — full-bundle verification: envelope checks, per-record
  Ed25519 signature + canonicalisation + afterHash parity,
  proof-chain walk, metering re-projection, settlement
  reconciliation.
- `verify_tenant_chain` — tenant append-only history verification.
- Offline-first: no network code; callers feed pinned
  `VerificationKey` sets (the regulator audit posture).
- Stable, enumerable `AuditReasonCode` set for regulator citation.
