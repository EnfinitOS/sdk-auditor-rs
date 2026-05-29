//! Tenant-level chain verification — Wave 27 / pre-pilot punch #1 Phase 4.
//!
//! Independently verifies the tenant-level chain that links every
//! rights-provenance row a tenant has ever written (Wave 25 / Phase 2).
//! Link shape:
//!
//! ```text
//! tenantChainNext_n = sha256(
//!     "tenantChain.v1|<prev>|<rowAfterHash>|<sequence>"
//! )
//! ```
//!
//! Pipe-delimited so this Rust verifier reconstructs the same bytes
//! the TypeScript writer produced — no canonical-JSON library needed.
//!
//! Cross-language conformance: a tenant chain written by the platform
//! (TypeScript) MUST verify here in Rust, and the reverse — a chain
//! built by the Rust test fixture MUST verify in the TS auditor and
//! the Python auditor. The smoke at `packages/sandbox-core/scripts/
//! smoke-proof-signing.mjs` exercises every direction.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{
    AuditReasonCode, AuditStep, AuditStepKind, AuditStepStatus, ChainAuditReport, SDK_VERSION,
};

/// Stable canonical chain-link version. Bumping requires a new
/// verifier path; never silently change without coordinating with
/// the TS and Python SDKs.
pub const TENANT_CHAIN_VERSION: &str = "tenantChain.v1";

/// One tenant-chained record. Decoupled from `ProofRecord` so this
/// verifier doesn't drag the entire receipt-side type system in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantChainedRecord {
    /// The row's content-addressable afterHash (entity chain).
    #[serde(rename = "rowAfterHash")]
    pub row_after_hash: String,
    /// The tenant-chain predecessor link, or `None` for the genesis row.
    #[serde(rename = "tenantChainPrev")]
    pub tenant_chain_prev: Option<String>,
    /// This row's tenant-chain link — what the next row will read as
    /// `tenantChainPrev`.
    #[serde(rename = "tenantChainNext")]
    pub tenant_chain_next: String,
    /// Monotonic position within the tenant. Stringified so JSON can
    /// carry the BigInt without precision loss.
    #[serde(rename = "tenantChainSequence")]
    pub tenant_chain_sequence: String,
}

/// Compute the canonical chain-link bytes the platform hashed at
/// write time. Pure; hand-rolled pipe-delimited form so cross-
/// language verifiers reconstruct without a canonical-JSON library.
pub fn canonicalise_tenant_chain_link(
    prev: Option<&str>,
    row_after_hash: &str,
    sequence: &str,
) -> String {
    let prev_str: &str = match prev {
        Some(s) if !s.is_empty() => s,
        _ => "-",
    };
    format!(
        "{}|{}|{}|{}",
        TENANT_CHAIN_VERSION, prev_str, row_after_hash, sequence
    )
}

/// Genesis seed value for a tenant. Length differs from any sha256
/// hex output (always 64 chars), so the seed cannot collide with a
/// real link hash.
pub fn genesis_chain_tip(org_id: &str) -> String {
    format!("provenance.{}.{}", TENANT_CHAIN_VERSION, org_id)
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let bytes = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in bytes.iter() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Verify the tenant-level chain across an array of rows.
///
/// Invariants checked, in order:
///   1. Sequence monotonicity. `records[i].tenant_chain_sequence`
///      MUST equal `records[i-1].tenant_chain_sequence + 1`. Gaps
///      or duplicates indicate inserted/dropped rows.
///   2. Prev linkage. For i ≥ 1, `records[i].tenant_chain_prev` MUST
///      equal `records[i-1].tenant_chain_next`. For i = 0 (genesis),
///      `tenant_chain_prev` MUST equal the supplied `expected_genesis`.
///   3. Next recomputation. `records[i].tenant_chain_next` MUST equal
///      `sha256(canonicalise_tenant_chain_link(prev, after, sequence))`.
///      Catches a tampered link that still chains correctly to the
///      neighbours but was forged.
///
/// Returns a `ChainAuditReport` — same shape as the TS SDK so a
/// regulator can render the two reports side-by-side.
pub fn verify_tenant_chain(
    records: &[TenantChainedRecord],
    expected_genesis: &str,
) -> ChainAuditReport {
    let verified_at = chrono_now_iso();
    let mut steps: Vec<AuditStep> = Vec::new();

    if records.is_empty() {
        steps.push(AuditStep {
            target: "records".into(),
            kind: AuditStepKind::ChainLink,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::MalformedPack),
            message: "tenant chain audit received an empty record set — nothing to verify".into(),
            detail: None,
        });
        return ChainAuditReport {
            status: AuditStepStatus::Invalid,
            verified_at,
            sdk_version: SDK_VERSION.to_string(),
            record_count: 0,
            steps,
        };
    }

    // 1. Genesis link.
    let first = &records[0];
    let first_prev = first.tenant_chain_prev.as_deref().unwrap_or("");
    if first_prev != expected_genesis {
        steps.push(AuditStep {
            target: "records[0].tenantChainPrev".into(),
            kind: AuditStepKind::ChainLink,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::ChainLinkMismatch),
            message:
                "first record's tenantChainPrev does not equal the expected genesis seed — chain is rooted at an unknown prior tip"
                    .into(),
            detail: Some(serde_json::json!({
                "expected": expected_genesis,
                "actual": first_prev,
            })),
        });
    } else {
        steps.push(AuditStep {
            target: "records[0].tenantChainPrev".into(),
            kind: AuditStepKind::ChainLink,
            status: AuditStepStatus::Valid,
            reason: None,
            message: "genesis prev seed matches the expected tenant seed".into(),
            detail: None,
        });
    }

    // 2. Walk: monotonicity, prev linkage, next recomputation.
    let mut prev_sequence: Option<u64> = None;
    for (i, curr) in records.iter().enumerate() {
        // Sequence monotonicity.
        let curr_sequence: u64 = match curr.tenant_chain_sequence.parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                steps.push(AuditStep {
                    target: format!("records[{}].tenantChainSequence", i),
                    kind: AuditStepKind::ChainLink,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::MalformedPack),
                    message: format!(
                        "tenantChainSequence at index {} is not a valid integer string",
                        i
                    ),
                    detail: Some(serde_json::json!({
                        "value": curr.tenant_chain_sequence,
                    })),
                });
                continue;
            }
        };
        if let Some(prev_seq) = prev_sequence {
            if curr_sequence != prev_seq + 1 {
                steps.push(AuditStep {
                    target: format!("records[{}].tenantChainSequence", i),
                    kind: AuditStepKind::ChainLink,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::ChainOutOfOrder),
                    message: format!(
                        "tenantChainSequence at index {} is {}, expected {} (gaps or duplicates indicate inserted/dropped rows)",
                        i,
                        curr_sequence,
                        prev_seq + 1,
                    ),
                    detail: Some(serde_json::json!({
                        "expected": (prev_seq + 1).to_string(),
                        "actual": curr_sequence.to_string(),
                    })),
                });
            }
        }
        prev_sequence = Some(curr_sequence);

        // Prev linkage (skip for genesis — covered above).
        if i > 0 {
            let prev = &records[i - 1];
            let curr_prev = curr.tenant_chain_prev.as_deref().unwrap_or("");
            if curr_prev != prev.tenant_chain_next {
                steps.push(AuditStep {
                    target: format!("records[{}].tenantChainPrev", i),
                    kind: AuditStepKind::ChainLink,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::ChainLinkMismatch),
                    message: format!(
                        "record[{}].tenantChainPrev does not equal record[{}].tenantChainNext — chain link broken",
                        i,
                        i - 1
                    ),
                    detail: Some(serde_json::json!({
                        "expected": prev.tenant_chain_next,
                        "actual": curr_prev,
                    })),
                });
            } else {
                steps.push(AuditStep {
                    target: format!("records[{}].tenantChainPrev", i),
                    kind: AuditStepKind::ChainLink,
                    status: AuditStepStatus::Valid,
                    reason: None,
                    message: format!("record[{}] correctly chains off record[{}]", i, i - 1),
                    detail: None,
                });
            }
        }

        // Next recomputation.
        let expected_next = sha256_hex(&canonicalise_tenant_chain_link(
            curr.tenant_chain_prev.as_deref(),
            &curr.row_after_hash,
            &curr_sequence.to_string(),
        ));
        if expected_next != curr.tenant_chain_next {
            steps.push(AuditStep {
                target: format!("records[{}].tenantChainNext", i),
                kind: AuditStepKind::ChainLink,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::ChainLinkMismatch),
                message: format!(
                    "record[{}].tenantChainNext does not equal the recomputed link — value was tampered with after write",
                    i
                ),
                detail: Some(serde_json::json!({
                    "expected": expected_next,
                    "actual": curr.tenant_chain_next,
                })),
            });
        } else {
            steps.push(AuditStep {
                target: format!("records[{}].tenantChainNext", i),
                kind: AuditStepKind::ChainLink,
                status: AuditStepStatus::Valid,
                reason: None,
                message: format!("record[{}].tenantChainNext matches the recomputed link", i),
                detail: None,
            });
        }
    }

    let any_invalid = steps.iter().any(|s| matches!(s.status, AuditStepStatus::Invalid));
    ChainAuditReport {
        status: if any_invalid {
            AuditStepStatus::Invalid
        } else {
            AuditStepStatus::Valid
        },
        verified_at,
        sdk_version: SDK_VERSION.to_string(),
        record_count: records.len(),
        steps,
    }
}

/// ISO-8601 timestamp. Uses chrono which is already a crate-level
/// dependency for the existing audit-report timestamps.
fn chrono_now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
