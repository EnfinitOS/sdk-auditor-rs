//! # enfinitos_auditor
//!
//! EnfinitOS **Auditor / Verifier SDK** — Rust port of the reference
//! [`@enfinitos/sdk-auditor`] TypeScript implementation. The wire
//! shapes, canonicalisation rules, and verification semantics are
//! deliberately identical: a regulator auditing the same proof pack
//! with either SDK MUST get the same VALID/INVALID verdict on every
//! step.
//!
//! ## Trust model
//!
//! EnfinitOS issues signed evidence as part of every spatial-chain run:
//! a proof receipt for every render, a metering summary projecting
//! those proofs into billable units, and a settlement summary
//! reconciling those units into invoiced amounts.
//!
//! The trust model is **"don't trust us — verify"**:
//!
//! 1. Every record is Ed25519-signed.
//! 2. Every proof receipt carries `before_hash` / `after_hash` so the
//!    chain detects single-record tampering.
//! 3. Metering is a deterministic projection of proof.
//! 4. Settlement is a deterministic projection of metering.
//! 5. The auditor SDK ships the same canonical-JSON encoder, projection
//!    formulae, and signature primitives, and so re-derives every claim
//!    the platform makes.
//!
//! The Rust crate is **offline-first** by design: it does not pull in
//! an HTTP client. Callers feed in a `VerificationKey` set they've
//! pinned themselves (the regulator audit posture).
//!
//! ## Example
//!
//! ```no_run
//! use enfinitos_auditor::{Auditor, AuditBundle, SignedProofPack, VerificationKey};
//! use std::fs;
//!
//! let pack_json = fs::read_to_string("pack.json").unwrap();
//! let pack: SignedProofPack = serde_json::from_str(&pack_json).unwrap();
//!
//! let keys_json = fs::read_to_string("keys.json").unwrap();
//! let keys: Vec<VerificationKey> = serde_json::from_str(&keys_json).unwrap();
//!
//! let auditor = Auditor::new(keys);
//! let report = auditor.verify_all(&AuditBundle {
//!     pack,
//!     metering: None,
//!     settlement: None,
//! });
//! println!("verdict: {:?}", report.status);
//! ```

#![deny(rust_2018_idioms)]
#![warn(clippy::all)]

pub mod auditor;
pub mod canonical_json;
pub mod errors;
pub mod hashing;
pub mod keys;
pub mod metering_audit;
pub mod proof_chain;
pub mod proof_pack;
pub mod settlement_audit;
pub mod tenant_chain;
pub mod types;

pub use auditor::Auditor;
pub use errors::{AuditorError, AuditorErrorCode};
pub use keys::KeyDirectory;
pub use tenant_chain::{
    canonicalise_tenant_chain_link, genesis_chain_tip, verify_tenant_chain,
    TenantChainedRecord, TENANT_CHAIN_VERSION,
};
pub use types::{
    AuditBundle, AuditReasonCode, AuditReport, AuditStep, AuditStepKind, AuditStepStatus,
    ChainAuditReport, EnvelopeVersion, FullAuditReport, KeysSnapshot, MeterRecord,
    MeterStatus, MeterUnitType, MeteringSummary, ProjectionAuditReport, ProofPack,
    ProofReceiptPayload, ProofRecord, SettlementAuditReport, SettlementLine,
    SettlementPartyRole, SettlementStatus, SettlementSummary, SettlementTotals,
    SignatureAlgorithm, SignedProofPack, VerificationKey, SDK_VERSION,
    SUPPORTED_ENVELOPE_VERSIONS, SUPPORTED_SIGNATURE_ALGORITHMS,
};
