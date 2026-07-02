# Changelog — enfinitos-sdk-auditor (Rust)

All notable changes to the Rust auditor SDK. Tracks the reference
TypeScript implementation (`@enfinitos/sdk-auditor` on npm)
release-for-release with identical wire shapes, reason codes, and
verdicts.

## 0.0.4 — 2026-07-02

### Added

- **Cross-pack chain anchor (`prior_after_hash`).** The platform seals
  proof packs in series: pack 2's `records[0].beforeHash` equals pack
  1's last `afterHash`, not null (`sealProofPack` threads
  `previousAfterHash`). `verify_proof_chain` gains a second parameter,
  `prior_after_hash: Option<&str>` — pass the previous pack's tail
  `afterHash` to verify cross-pack continuity; a mismatch reports
  `CHAIN_LINK_MISMATCH`. `None` keeps the legacy genesis invariant
  (`records[0].before_hash == None`) unchanged. Threaded through
  `Auditor::verify_proof_chain` and `Auditor::verify_all` via the new
  `AuditBundle.prior_after_hash: Option<String>` field. Mirrors the TS
  `priorAfterHash` semantics exactly.
- **Legacy `settlement.v1` verification (VER-02).** New
  `hashing::settlement_idem_key_v1(meter_record_idem_key, party_role)`
  — the 2-field `sha256(meterIdemKey|partyRole)` used by packs sealed
  before the CRYPTO-01 / `settlement.v2` flip.
  `verify_settlement_reconciliation` now selects the reconstruction
  formula by the summary's `schema_version`, so genuine historical
  `settlement.v1` evidence verifies VALID instead of every line
  flagging `SETTLEMENT_IDEM_KEY_MISMATCH`. This supersedes the 0.0.3
  migration note below — re-issuing v1 summaries is no longer
  required.
- **Signed-export verification (`verify_signed_export`)** — verifies
  the `export.v1` envelopes the platform issues from
  `GET /v1/metering?export=true` and `GET /v1/settlement?export=true`:
  key-directory lookup (validity window anchored at `exportedAt`),
  payload re-canonicalisation (`canonical_sort_keys`),
  transparency-hash check, and Ed25519 `verify_strict` over
  `"{payloadCanonical}|{keyId}"`. New `exports` module with
  `SignedExport` (serde wire shape, camelCase keys) and
  `SignedExportAuditReport`, both re-exported at the crate root. New
  reason code `AuditReasonCode::ExportPayloadHashMismatch`
  (`EXPORT_PAYLOAD_HASH_MISMATCH`); all other failures reuse the
  existing envelope / key / canonicalisation / signature codes. After
  the signature gate passes, deserialise `export.payload` into the
  summary type and feed it to `verify_metering_projection` /
  `verify_settlement_reconciliation` for the content checks.

### Changed (source-breaking, wire-compatible)

- `verify_proof_chain(records)` → `verify_proof_chain(records,
  prior_after_hash)` (both the free function and the `Auditor`
  method). Existing callers pass `None` for the old behaviour.
- `AuditBundle` gains the `prior_after_hash: Option<String>` field —
  struct-literal constructions must add `prior_after_hash: None`.
- `AuditReasonCode` gains the `ExportPayloadHashMismatch` variant —
  exhaustive `match`es over the enum need a new arm.
- `SDK_VERSION` constant (stamped onto every audit report) bumped to
  `"0.0.4"`.

### Publishing note

- **The published 0.0.2 packages fail every settlement.v2 pack the
  platform now issues** (every line flags
  `SETTLEMENT_IDEM_KEY_MISMATCH` under the old 2-field key). 0.0.4 is
  the minimum version that verifies current packs — republish
  npm/PyPI/crates together and treat 0.0.2/0.0.3 as superseded.

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
