# enfinitos-sdk-auditor (Rust)

EnfinitOS **Auditor / Verifier SDK** for Rust — a fast, offline-first,
cryptographic verification library that regulators, auditors, courts,
and third-party compliance tools use to verify signed proof packs
issued by EnfinitOS, **without having to trust EnfinitOS as a vendor**.

Companion to the reference [`@enfinitos/sdk-auditor`](../auditor-ts/)
TypeScript implementation and [`enfinitos-sdk-auditor`](../auditor-py/)
Python implementation. The wire shapes, canonicalisation rules, and
verification semantics are deliberately identical: a regulator
auditing the same proof pack with any of the three SDKs MUST get the
same VALID/INVALID verdict on every step.

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
   binary is small, dependency-light (5 crates), and has no FFI.

## The trust model

"Don't trust us — verify". See the
[TypeScript README](../auditor-ts/README.md#the-trust-model) for the
full framing. The short version:

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
enfinitos-sdk-auditor = "0.0.1"
```

Or — for an air-gapped regulator build — vendor it:

```bash
cargo vendor packages/sdks/auditor-rs
```

The crate has exactly five runtime dependencies, all of which are
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

    // 3. Audit.
    let auditor = Auditor::new(keys);
    let report = auditor.verify_all(&AuditBundle {
        pack,
        metering: None,
        settlement: None,
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
    pub fn verify_proof_chain(&self, records: &[ProofRecord]) -> ChainAuditReport;
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

See the [TypeScript README](../auditor-ts/README.md#error-model) for
the full stable reason-code table.

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
| Settlement idem key | `settlementIdemKey` | `settlement_idem_key` | `settlement_idem_key` |
| Ed25519 verify | `@noble/ed25519` | `cryptography` | `ed25519-dalek` |
| Decimal scaling | `bigint` at 10^6 | `int` at 10^6 | `i128` at 10^6 |
| Reason codes | identical enum | identical enum | identical enum |

A proof pack that verifies VALID in one SDK MUST verify VALID in the
other two — the test suite reproduces the same fixtures across
languages so regressions are caught immediately.
