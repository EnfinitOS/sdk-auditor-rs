# enfinitos-sdk-auditor (Rust)

EnfinitOS **Auditor / Verifier SDK** for Rust — a fast, offline-first,
cryptographic verification library that regulators, auditors, courts,
and third-party compliance tools use to verify signed proof packs
issued by EnfinitOS, **without having to trust EnfinitOS as a vendor**.

Companion to the reference
[`@enfinitos/sdk-auditor`](https://github.com/EnfinitOS/sdk-auditor-ts)
TypeScript implementation and
[`enfinitos-sdk-auditor`](https://github.com/EnfinitOS/sdk-auditor-py)
Python implementation. The wire shapes, canonicalisation rules, and
verification semantics are deliberately identical: a regulator
auditing the same proof pack with any of the three SDKs MUST get the
same VALID/INVALID verdict on every step.

## What's new in 0.0.4

**Settlement verification is version-aware (`settlement.v1` + `settlement.v2`).**
The current settlement idem key is 3-field and content-hash based (CRYPTO-01):
`settlement_idem_key(meter_record_idem_key, party_role, ledger_account_code)` =
`sha256(meterRecordIdemKey|partyRole|ledgerAccountCode)`, matching the
production settlement engine. Packs stamped `settlement.v1` (sealed before the
CRYPTO-01 flip) still verify: the auditor selects the legacy 2-field
`sha256(meterRecordIdemKey|partyRole)` reconstruction
(`settlement_idem_key_v1`) by the summary's `schemaVersion` (VER-02), so
genuine historical evidence is never reported as tampered. **Cross-pack
chains** verify via the new `prior_after_hash: Option<&str>` parameter on
`verify_proof_chain` (and `AuditBundle.prior_after_hash`) — pass the previous
pack's tail `afterHash` when verifying a later pack in a tenant's chain (the
platform seals packs in series). **Signed exports** (`?export=true`
metering/settlement envelopes) verify offline via `verify_signed_export`. See
[CHANGELOG.md](https://github.com/EnfinitOS/sdk-auditor-rs/blob/main/CHANGELOG.md).

## What's new in 0.0.2

**Rights-provenance write-time signature verification.** The platform
now Ed25519-signs every rights-provenance ledger row at write time
(basis, right, offer, and challenge lifecycle events); 0.0.2 ships
the independent verifier:

```rust
use enfinitos_auditor::{
    verify_provenance_chain, KeyDirectory, VerifyProvenanceChainOptions,
};

let directory = KeyDirectory::from_local(pinned_keys)?;
let report = verify_provenance_chain(
    &export_archive_records, // Vec<ProvenanceRecord> from /proof/export
    &directory,
    &VerifyProvenanceChainOptions {
        expected_org_id: Some("org_abc".to_string()),
    },
);
report.status;                // Valid | Invalid | Skipped
report.signed_record_count;   // write-time-signed records
report.unsigned_record_count; // legacy (pre-write-time) records
```

Legacy records (pre-write-time signing, `signatureAlgorithm:
"hmac-sha256"`) surface as informational SKIPPED findings — never
INVALID — so 0.0.1-era exports keep verifying.

**Upgrade note (Rust-specific):** 0.0.2 widens `SettlementPartyRole`
to the platform's full 8-role union (`AGENCY`, `AFFILIATE`,
`RESELLER`, `TAX_AUTHORITY` added). The 0.0.1 crate's strict serde
enum **rejected at deserialisation** any pack whose settlement lines
used one of the new roles; 0.0.2 deserialises and verifies them. If
you audit packs from tenants on counterparty-addressed settlement,
upgrade. See
[CHANGELOG.md](https://github.com/EnfinitOS/sdk-auditor-rs/blob/main/CHANGELOG.md)
for the full release notes.

## Why Rust?

The Python and TypeScript SDKs cover most regulator and customer
workflows. The Rust SDK exists to:

1. **Demonstrate offline verification works without our infrastructure.**
   The crate has zero network code. It accepts pinned keys and proof
   packs from disk, computes a verdict, and shuts down.
2. **Enable high-throughput bulk verification.** A central regulator
   or audit firm replaying millions of proof packs benefits from
   Rust's throughput and zero-allocation hot paths.
3. **Allow embedding inside an air-gapped audit appliance** — the
   binary is small, dependency-light (7 crates), and has no FFI.

## The trust model

"Don't trust us — verify". See the
[TypeScript README](https://github.com/EnfinitOS/sdk-auditor-ts#the-trust-model)
for the full framing. The short version:

1. We Ed25519-sign every record. The public keys are published.
2. Every proof receipt is hash-chained.
3. Metering is a deterministic projection of proof receipts.
4. Settlement is a deterministic projection of metering.
5. This crate ships byte-exact replicas of every encoder, projector,
   and signature primitive the platform uses, and so re-derives every
   claim independently.

## Installation

```toml
[dependencies]
enfinitos-sdk-auditor = "0.0.4"
```

Or — for an air-gapped regulator build — vendor it:

```bash
cargo vendor packages/sdks/auditor-rs
```

The crate has exactly seven runtime dependencies, all of which are
well-known and well-audited:

| Crate | Why |
|---|---|
| `ed25519-dalek` | Pure-Rust Ed25519 signature verify primitive |
| `serde` + `serde_json` | JSON parse / re-serialise for proof packs |
| `sha2` | SHA-256 hashing |
| `base64` | base64url encode/decode for signature + public key |
| `chrono` | ISO-8601 parsing for key validity windows |
| `thiserror` | Ergonomic error types |

## Five-minute getting started

```rust
use std::fs;
use enfinitos_auditor::{AuditBundle, Auditor, SignedProofPack, VerificationKey};

fn main() {
    // 1. Load the pinned verification key set (regulator path).
    let keys_json = fs::read_to_string("./pinned-keys.json").unwrap();
    let keys: Vec<VerificationKey> = serde_json::from_str(&keys_json).unwrap();

    // 2. Load the proof pack the operator handed over.
    let pack_json = fs::read_to_string("./pack.json").unwrap();
    let pack: SignedProofPack = serde_json::from_str(&pack_json).unwrap();

    // 3. Audit. (Pass the previous pack's tail afterHash as
    // `prior_after_hash` when verifying a later pack in a tenant's
    // chain; None for a standalone / first pack.)
    let auditor = Auditor::new(keys);
    let report = auditor.verify_all(&AuditBundle {
        pack,
        metering: None,
        settlement: None,
        prior_after_hash: None,
    });

    // 4. Print verdict.
    println!("{:?}", report.status);
    if report.status != enfinitos_auditor::AuditStepStatus::Valid {
        for s in &report.pack.steps {
            if s.status == enfinitos_auditor::AuditStepStatus::Invalid {
                eprintln!("[{:?}] {}: {}", s.reason, s.target, s.message);
            }
        }
    }
}
```

## Getting the platform keys

The crate is deliberately offline — it never makes HTTP calls. Fetch
the platform's signing-key directory yourself and feed it in. UNTIL
THE APRIL 2027 LAUNCH the live endpoint is the sandbox
(`api.enfinitos.com` is not live yet):

```sh
# Today (sandbox). At launch: https://api.enfinitos.com/v1/runtime-keys
curl -s https://sandbox.api.enfinitos.com/v1/runtime-keys > runtime-keys.json
```

The response is the platform's `{ ok, data: { keys, issuedAt } }`
envelope — parse it with the built-in helper instead of unwrapping by
hand:

```rust
use std::fs;
use enfinitos_auditor::KeyDirectory;

let json = fs::read_to_string("./runtime-keys.json").unwrap();
let directory = KeyDirectory::from_runtime_keys_json(&json).unwrap();
```

For the regulator path (keys pinned out-of-band, fully air-gapped),
use `KeyDirectory::from_local(keys)` with a `Vec<VerificationKey>` as
in the five-minute example above.

## Architecture

```
                ┌─────────────────────────────────────────┐
                │           SignedProofPack JSON          │
                │     (envelope.v1, signed by EnfinitOS)  │
                └────────────────────┬────────────────────┘
                                     │
                                     ▼
                ┌─────────────────────────────────────────┐
                │   serde_json::from_str → SignedProofPack │
                └────────────────────┬────────────────────┘
                                     │
                ┌────────────────────┴────────────────────┐
                │                                         │
                ▼                                         ▼
   ┌────────────────────────────┐         ┌─────────────────────────┐
   │   verify_proof_record × N  │         │   verify_proof_chain    │
   │   (proof_pack.rs)          │         │   (proof_chain.rs)      │
   └────────────────────────────┘         └─────────────────────────┘
                  │
                  ▼
   ┌────────────────────────────┐
   │  verify_metering_projection│
   │     (metering_audit.rs)    │
   └─────────────┬──────────────┘
                 │
                 ▼
   ┌────────────────────────────┐
   │ verify_settlement_reconcil.│
   │   (settlement_audit.rs)    │
   └─────────────┬──────────────┘
                 │
                 ▼
   ┌────────────────────────────┐
   │     FullAuditReport        │
   │   { status, sub-reports }  │
   └────────────────────────────┘
```

## Sample workflows

### "I'm a regulator inspecting a campaign's evidence"

```rust
let keys = load_pinned_keys();
let auditor = Auditor::new(keys);
let report = auditor.verify_all(&bundle);
// Every step has a stable reason code; cite them in your report.
```

### "I'm an audit firm batch-verifying 100k packs"

```rust
let auditor = Auditor::new(keys);
let mut invalid_packs: Vec<String> = Vec::new();
for pack_path in pack_paths {
    let pack: SignedProofPack = serde_json::from_str(
        &std::fs::read_to_string(&pack_path).unwrap(),
    ).unwrap();
    let report = auditor.verify_all(&AuditBundle {
        pack,
        metering: None,
        settlement: None,
        prior_after_hash: None,
    });
    if report.status != AuditStepStatus::Valid {
        invalid_packs.push(pack_path);
    }
}
```

## API reference

### `Auditor`

```rust
impl Auditor {
    pub fn new(keys: Vec<VerificationKey>) -> Self;
    pub fn with_directory(dir: KeyDirectory) -> Self;
    pub fn from_runtime_keys_json(json: &str) -> Result<Self, AuditorError>;

    pub fn verify_proof_pack(&self, pack: &SignedProofPack) -> AuditReport;
    pub fn verify_proof_chain(
        &self,
        records: &[ProofRecord],
        prior_after_hash: Option<&str>,
    ) -> ChainAuditReport;
    pub fn verify_metering_projection(
        &self,
        records: &[ProofRecord],
        metering: &MeteringSummary,
        pack_org_id: Option<&str>,
    ) -> ProjectionAuditReport;
    pub fn verify_settlement_reconciliation(
        &self,
        metering: &MeteringSummary,
        settlement: &SettlementSummary,
    ) -> SettlementAuditReport;
    pub fn verify_all(&self, bundle: &AuditBundle) -> FullAuditReport;
}
```

See `src/types.rs` for the full data model. Every wire field uses the
same JSON name as the TS/Py ports, so a JSON proof pack flows through
all three SDKs unchanged.

## Error model

Two failure classes (identical to the other SDKs):

1. **Audit failures** — pack contents fail verification. Returned
   inside `AuditReport.steps[]` with a stable `AuditReasonCode`.
   Never panic.
2. **Operational errors** — the SDK can't run. Returned as
   `AuditorError` with an `AuditorErrorCode`.

See the
[TypeScript README](https://github.com/EnfinitOS/sdk-auditor-ts#error-model)
for the full stable reason-code table.

## Verification

```bash
cd packages/sdks/auditor-rs
cargo build      # offline-friendly when ./vendor is populated
cargo test       # runs the integration suite
```

If `cargo` isn't available, the source compiles syntactically and is
covered by the equivalent test suites in the TS and Python ports.

## Cross-language parity

The three SDKs are kept byte-for-byte identical at the wire boundary:

| Concern | TypeScript | Python | Rust |
|---|---|---|---|
| Canonical proof payload | `canonicaliseProofPayload` | `canonicalise_proof_payload` | `canonicalise_proof_payload` |
| Sort-key encoder | `canonicalSortKeys` | `canonical_sort_keys` | `canonical_sort_keys` |
| Meter idem key | `meterIdemKey` | `meter_idem_key` | `meter_idem_key` |
| Settlement idem key (v2) | `settlementIdemKey` | `settlement_idem_key` | `settlement_idem_key` |
| Settlement idem key (legacy v1) | `settlementIdemKeyV1` | `settlement_idem_key_v1` | `settlement_idem_key_v1` |
| Cross-pack chain anchor | `priorAfterHash` | `prior_after_hash` | `prior_after_hash` |
| Signed exports (export.v1) | `verifySignedExport` | `verify_signed_export` | `verify_signed_export` |
| Ed25519 verify | `@noble/ed25519` | `cryptography` | `ed25519-dalek` |
| Decimal scaling | `bigint` at 10^6 | `int` at 10^6 | `i128` at 10^6 |
| Reason codes | identical enum | identical enum | identical enum |

A proof pack that verifies VALID in one SDK MUST verify VALID in the
other two — the test suite reproduces the same fixtures across
languages so regressions are caught immediately.
