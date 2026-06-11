//! Rights-provenance write-time signature verification — Wave 14
//! Phase 2. Rust port of the TS reference `provenance.ts`; identical
//! canonical-string construction, reason codes, report shape, and
//! legacy posture, so a regulator auditing the same record set with
//! either SDK gets the same verdict on every step.
//!
//! Independently verifies the per-record Ed25519 signatures the
//! platform computes at write time on every rights-provenance row
//! (apps/api/src/modules/rights/provenanceSigner.ts): basis
//! assert/verify/reject, right issue/suspend/resume/revoke/expire,
//! offer propose/accept/counter/reject/withdraw/expire, and challenge
//! open/resolve/withdraw.
//!
//! The signing input is a flat pipe-delimited string — NOT canonical
//! JSON — so TS / Rust / Python verifiers reconstruct the exact bytes
//! without sharing a canonical-JSON library:
//!
//! ```text
//! "rightProvenance.v1|<orgId>|<eventType>|<rightId|->|<basisId|->|
//!  <offerId|->|<beforeHash|->|<afterHash|->|<keyId>"
//! ```
//!
//! where `-` encodes absence (None or empty string — the platform
//! deliberately collapses the two so an absent rightId cannot collide
//! with a literal empty-string rightId).
//!
//! Verification path per record
//! ----------------------------
//!   ed25519 records (write-time signed):
//!     1. Re-derive the canonical signing input from the record's raw
//!        fields + signer_key_id, and assert byte-equality against
//!        the record's `payload_canonical` transparency field
//!        (PROVENANCE_CANONICAL_MISMATCH on divergence).
//!     2. Look the signer_key_id up in the KeyDirectory; reject if
//!        missing / outside validity window / revoked
//!        (UNKNOWN_KEY_ID / KEY_OUTSIDE_VALIDITY_WINDOW /
//!        KEY_REVOKED_BEFORE_ISSUANCE — same codes as receipts).
//!     3. Decode the base64url signature + public key
//!        (PROVENANCE_SIGNATURE_MALFORMED if not strict base64url or
//!        not 64/32 bytes).
//!     4. Ed25519-verify the signature over the canonical bytes
//!        (PROVENANCE_SIGNATURE_INVALID on failure).
//!
//!   hmac-sha256 records (legacy, pre-Wave-14):
//!     The platform synthesised a read-time transport HMAC; there is
//!     nothing write-signed for an independent party to verify. The
//!     verifier reports a single SKIPPED step per record carrying the
//!     informational reason PROVENANCE_UNSIGNED_RECORD — NEVER an
//!     INVALID. Published 0.0.1-era exports keep verifying, with the
//!     unsigned records clearly labelled.
//!
//! Relationship to the other chain verifiers
//! -----------------------------------------
//! This module verifies WHO wrote each row (non-repudiation). It is
//! deliberately orthogonal to:
//!   - `tenant_chain` — verifies the rows' POSITION in the tenant's
//!     append-only history (insertion/rewrite detection). Run both
//!     for the full provenance posture.
//!   - `proof_chain` — the spatial-chain receipt walker; receipts are
//!     a different artefact with a different canonical encoding.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::canonical_json::base64url_decode_strict;
use crate::keys::{KeyDirectory, KeyLookupResult, KeyMissReason};
use crate::types::{
    AuditReasonCode, AuditStep, AuditStepKind, AuditStepStatus, ProvenanceAuditReport,
    ProvenanceRecord, SDK_VERSION,
};

/// Stable canonical signing-input version tag.
pub const PROVENANCE_SIGNING_VERSION: &str = "rightProvenance.v1";

/// The subset of [`ProvenanceRecord`] fields that participate in the
/// canonical signing input. Kept as its own type so callers building
/// conformance fixtures don't have to fabricate the envelope fields.
#[derive(Debug, Clone)]
pub struct ProvenanceSigningFields {
    pub org_id: String,
    /// The platform's raw lifecycle event tag (e.g. RIGHT_ISSUED).
    pub event_type: String,
    pub right_id: Option<String>,
    pub basis_id: Option<String>,
    pub offer_id: Option<String>,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
}

/// Reconstruct the exact canonical string the platform signed at
/// write time. Pure; byte-for-byte parity with
/// apps/api/src/modules/rights/provenanceSigner.ts
/// `canonicaliseProvenanceSigningInput` and the TS / Python SDK
/// ports. Absence (None or empty string) encodes as `-`.
pub fn canonicalise_provenance_signing_input(
    fields: &ProvenanceSigningFields,
    key_id: &str,
) -> String {
    fn f(v: Option<&str>) -> &str {
        match v {
            Some(s) if !s.is_empty() => s,
            _ => "-",
        }
    }
    [
        PROVENANCE_SIGNING_VERSION,
        f(Some(fields.org_id.as_str())),
        f(Some(fields.event_type.as_str())),
        f(fields.right_id.as_deref()),
        f(fields.basis_id.as_deref()),
        f(fields.offer_id.as_deref()),
        f(fields.before_hash.as_deref()),
        f(fields.after_hash.as_deref()),
        f(Some(key_id)),
    ]
    .join("|")
}

// ---------------------------------------------------------------------
// Per-record verification
// ---------------------------------------------------------------------

/// Verify one rights-provenance record's write-time signature.
/// Returns audit steps mirroring the receipt-side
/// `verify_proof_record` shape:
///
///   - legacy (hmac-sha256) record → one SKIPPED step with the
///     informational reason PROVENANCE_UNSIGNED_RECORD.
///   - ed25519 record → canonicalisation step, key-lookup step,
///     signature step; each VALID or INVALID with a structured reason.
pub fn verify_provenance_record(
    record: &ProvenanceRecord,
    record_index: usize,
    keys: &KeyDirectory,
) -> Vec<AuditStep> {
    let mut steps: Vec<AuditStep> = Vec::with_capacity(3);
    let target = |suffix: &str| format!("provenance[{record_index}].{suffix}");

    // Legacy partition — informational, never a failure. There is no
    // write-time signature to verify; the platform's honest-history
    // decision at Wave 14 was to tag rather than back-sign.
    if record.signature_algorithm != "ed25519" {
        steps.push(AuditStep {
            target: target("signature"),
            kind: AuditStepKind::ProvenanceSignature,
            status: AuditStepStatus::Skipped,
            reason: Some(AuditReasonCode::ProvenanceUnsignedRecord),
            message:
                "record pre-dates write-time provenance signing (read-time HMAC only) — not independently verifiable; informational, not a failure"
                    .to_string(),
            detail: Some(serde_json::json!({
                "signatureAlgorithm": record.signature_algorithm,
                "provenanceEventType": record.provenance_event_type,
            })),
        });
        return steps;
    }

    // 1. Canonical-input parity. The record ships `payload_canonical`
    // as a transparency aid; we re-derive from the raw fields and
    // compare byte-for-byte. A divergence means the raw fields were
    // edited after signing, or the canonicaliser version skewed.
    let reconstructed = canonicalise_provenance_signing_input(
        &ProvenanceSigningFields {
            org_id: record.org_id.clone(),
            event_type: record.provenance_event_type.clone(),
            right_id: record.right_id.clone(),
            basis_id: record.basis_id.clone(),
            offer_id: record.offer_id.clone(),
            before_hash: record.provenance_before_hash.clone(),
            after_hash: record.provenance_after_hash.clone(),
        },
        &record.signer_key_id,
    );
    let shipped_canonical = match record.payload_canonical.as_deref() {
        None => {
            steps.push(AuditStep {
                target: target("payloadCanonical"),
                kind: AuditStepKind::ProvenanceSignature,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::ProvenanceCanonicalMismatch),
                message:
                    "ed25519 record carries no payloadCanonical — the signed bytes cannot be attested; partial-fill violates the write-time signing contract"
                        .to_string(),
                detail: None,
            });
            return steps;
        }
        Some(s) => s,
    };
    if reconstructed != shipped_canonical {
        steps.push(AuditStep {
            target: target("payloadCanonical"),
            kind: AuditStepKind::ProvenanceSignature,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::ProvenanceCanonicalMismatch),
            message:
                "the canonical signing input the SDK reconstructed from the record's raw fields does not match the bytes the record ships — field tampering or canonicaliser version skew"
                    .to_string(),
            detail: Some(serde_json::json!({
                "expected": truncate_256(shipped_canonical),
                "actual": truncate_256(&reconstructed),
            })),
        });
        // Continue: the signature step over the SHIPPED canonical
        // bytes still tells the auditor whether the signature is at
        // least internally consistent — useful forensics either way.
    } else {
        steps.push(AuditStep {
            target: target("payloadCanonical"),
            kind: AuditStepKind::ProvenanceSignature,
            status: AuditStepStatus::Valid,
            reason: None,
            message: "canonical signing input reconstructs from the raw fields".to_string(),
            detail: None,
        });
    }

    // 2. Key lookup — same directory + validity-window semantics as
    // the receipt verifier; `occurred_at` plays the role of issuedAt.
    let key = match keys.lookup(&record.signer_key_id, &record.occurred_at) {
        KeyLookupResult::Hit(k) => k,
        KeyLookupResult::Miss(reason) => {
            let code = match reason {
                KeyMissReason::UnknownKeyId => AuditReasonCode::UnknownKeyId,
                KeyMissReason::OutsideValidityWindow => {
                    AuditReasonCode::KeyOutsideValidityWindow
                }
                KeyMissReason::RevokedBeforeIssuance => {
                    AuditReasonCode::KeyRevokedBeforeIssuance
                }
            };
            let reason_str = match reason {
                KeyMissReason::UnknownKeyId => "UNKNOWN_KEY_ID",
                KeyMissReason::OutsideValidityWindow => "KEY_OUTSIDE_VALIDITY_WINDOW",
                KeyMissReason::RevokedBeforeIssuance => "KEY_REVOKED_BEFORE_ISSUANCE",
            };
            steps.push(AuditStep {
                target: target("signerKeyId"),
                kind: AuditStepKind::KeyLookup,
                status: AuditStepStatus::Invalid,
                reason: Some(code),
                message: format!(
                    "provenance signing key '{}' rejected: {}",
                    record.signer_key_id, reason_str
                ),
                detail: Some(serde_json::json!({
                    "signerKeyId": record.signer_key_id,
                    "occurredAt": record.occurred_at,
                })),
            });
            return steps;
        }
    };
    steps.push(AuditStep {
        target: target("signerKeyId"),
        kind: AuditStepKind::KeyLookup,
        status: AuditStepStatus::Valid,
        reason: None,
        message: format!(
            "key '{}' resolved and valid for occurredAt",
            record.signer_key_id
        ),
        detail: None,
    });

    // 3. Decode signature + public key — strict base64url (unpadded).
    let sig_bytes = match base64url_decode_strict(&record.signature) {
        Ok(b) => b,
        Err(e) => {
            steps.push(malformed_step(
                target("signature"),
                format!("signature/public-key decoding failed: {e}"),
            ));
            return steps;
        }
    };
    let pub_bytes = match base64url_decode_strict(&key.public_key) {
        Ok(b) => b,
        Err(e) => {
            steps.push(malformed_step(
                target("signature"),
                format!("signature/public-key decoding failed: {e}"),
            ));
            return steps;
        }
    };
    if sig_bytes.len() != 64 || pub_bytes.len() != 32 {
        steps.push(malformed_step(
            target("signature"),
            format!(
                "expected 64-byte signature / 32-byte public key, got {} / {}",
                sig_bytes.len(),
                pub_bytes.len()
            ),
        ));
        return steps;
    }

    // 4. Ed25519 verify — over the SHIPPED canonical bytes (the exact
    // bytes the platform claims it signed). If step 1 already flagged
    // a canonical mismatch, a VALID result here means "internally
    // consistent signature over tampered claims" — the report is
    // already INVALID from step 1, so no failure is masked.
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes[..32]);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes[..64]);

    let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
        Ok(k) => k,
        Err(_) => {
            // Not a valid Ed25519 point — the signature cannot
            // possibly verify against this key.
            steps.push(AuditStep {
                target: target("signature"),
                kind: AuditStepKind::ProvenanceSignature,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::ProvenanceSignatureInvalid),
                message: "signature verify threw: public key was not a valid Ed25519 point"
                    .to_string(),
                detail: None,
            });
            return steps;
        }
    };
    let signature = Signature::from_bytes(&sig_arr);
    // CRYPTO-02: strict verification (canonical S + reject small-order) so this
    // Rust verifier shares an acceptance set with the TS/Python verifiers.
    let ok = verifying_key
        .verify_strict(shipped_canonical.as_bytes(), &signature)
        .is_ok();

    steps.push(AuditStep {
        target: target("signature"),
        kind: AuditStepKind::ProvenanceSignature,
        status: if ok {
            AuditStepStatus::Valid
        } else {
            AuditStepStatus::Invalid
        },
        reason: if ok {
            None
        } else {
            Some(AuditReasonCode::ProvenanceSignatureInvalid)
        },
        message: if ok {
            "Ed25519 write-time signature verifies against the declared key".to_string()
        } else {
            "Ed25519 write-time signature did NOT verify — the record was tampered with after signing, or the signerKeyId points to a different key than the one that signed it"
                .to_string()
        },
        detail: None,
    });

    steps
}

fn malformed_step(target: String, message: String) -> AuditStep {
    AuditStep {
        target,
        kind: AuditStepKind::ProvenanceSignature,
        status: AuditStepStatus::Invalid,
        reason: Some(AuditReasonCode::ProvenanceSignatureMalformed),
        message,
        detail: None,
    }
}

fn truncate_256(s: &str) -> &str {
    // Canonical signing inputs are ASCII; the 256 cut never splits a
    // multi-byte boundary on real platform data. Guard anyway.
    let mut end = 256.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------
// Chain-level verification
// ---------------------------------------------------------------------

/// Options for [`verify_provenance_chain`].
#[derive(Debug, Clone, Default)]
pub struct VerifyProvenanceChainOptions {
    /// When supplied, every record's org_id must match — a
    /// mixed-tenant record set is reported as PROVENANCE_ORG_MISMATCH
    /// (a spliced export). Omit for multi-tenant forensic walks.
    pub expected_org_id: Option<String>,
}

/// Verify the write-time signatures across a rights-provenance record
/// set (e.g. the records array of a `/proof/export` archive, or a
/// `/proof/:id/chain` walk).
///
/// Per record this runs [`verify_provenance_record`]; legacy
/// (hmac-sha256) records surface as informational SKIPPED steps with
/// the PROVENANCE_UNSIGNED_RECORD reason and never fail the report.
///
/// Report status:
///   - INVALID if any step is INVALID;
///   - VALID if at least one record verified and none failed;
///   - SKIPPED if every record was legacy (nothing was verifiable) —
///     conservative: a fully-unsigned set must not be promoted to
///     VALID just because nothing contradicted it.
///
/// Backwards compatibility: exports produced before the platform
/// shipped write-time provenance signing verify as SKIPPED with
/// informational findings only — never INVALID.
///
/// NOTE: this primitive proves WHO signed each record. To prove the
/// records' POSITION in the tenant's append-only history (insertion /
/// rewrite detection), additionally run [`crate::verify_tenant_chain`]
/// over the same records' tenant-chain fields.
pub fn verify_provenance_chain(
    records: &[ProvenanceRecord],
    keys: &KeyDirectory,
    options: &VerifyProvenanceChainOptions,
) -> ProvenanceAuditReport {
    let verified_at = chrono_now_iso();
    let mut steps: Vec<AuditStep> = Vec::new();
    let mut signed_record_count: usize = 0;
    let mut unsigned_record_count: usize = 0;

    if records.is_empty() {
        return ProvenanceAuditReport {
            status: AuditStepStatus::Invalid,
            verified_at,
            sdk_version: SDK_VERSION.to_string(),
            record_count: 0,
            signed_record_count: 0,
            unsigned_record_count: 0,
            steps: vec![AuditStep {
                target: "records".to_string(),
                kind: AuditStepKind::ProvenanceSignature,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::MalformedPack),
                message:
                    "provenance signature audit received an empty record set — nothing to verify"
                        .to_string(),
                detail: None,
            }],
        };
    }

    for (i, record) in records.iter().enumerate() {
        // Org consistency — a spliced multi-tenant export is rejected
        // before the signature even runs (the signature would verify;
        // the splice is at the SET level, not the record level).
        if let Some(expected) = options.expected_org_id.as_deref() {
            if record.org_id != expected {
                steps.push(AuditStep {
                    target: format!("provenance[{i}].orgId"),
                    kind: AuditStepKind::ProvenanceSignature,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::ProvenanceOrgMismatch),
                    message: format!(
                        "record orgId '{}' does not match the expected orgId '{}' — record set spliced across tenants",
                        record.org_id, expected
                    ),
                    detail: Some(serde_json::json!({
                        "expected": expected,
                        "actual": record.org_id,
                    })),
                });
            }
        }

        if record.signature_algorithm == "ed25519" {
            signed_record_count += 1;
        } else {
            unsigned_record_count += 1;
        }

        steps.extend(verify_provenance_record(record, i, keys));
    }

    let any_invalid = steps
        .iter()
        .any(|s| matches!(s.status, AuditStepStatus::Invalid));
    let any_valid = steps
        .iter()
        .any(|s| matches!(s.status, AuditStepStatus::Valid));
    let status = if any_invalid {
        AuditStepStatus::Invalid
    } else if any_valid {
        AuditStepStatus::Valid
    } else {
        AuditStepStatus::Skipped
    };

    ProvenanceAuditReport {
        status,
        verified_at,
        sdk_version: SDK_VERSION.to_string(),
        record_count: records.len(),
        signed_record_count,
        unsigned_record_count,
        steps,
    }
}

/// ISO-8601 timestamp — same crate-level convention as the other
/// audit-report producers.
fn chrono_now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
