//! Signed-export verification (export.v1).
//!
//! The platform signs its metering + settlement summaries on demand
//! (`GET /v1/metering?export=true`, `GET /v1/settlement?export=true`) into a
//! `SignedExport` envelope so a third party can hold a portable, offline-
//! verifiable copy of the money-plane numbers — the same "verify us without
//! trusting us" guarantee the proof packs carry. This module is the verifier
//! side; the signer is `packages/sandbox-core/src/exports.ts` and the two are
//! byte-parity mirrors (as is the TS reference verifier,
//! `auditor-ts/src/exports.ts`):
//!
//! ```text
//! payload_canonical      = canonical_sort_keys(payload)   (recursive
//!                          lexicographic key sort, array order preserved)
//! payload_canonical_hash = sha256 hex (bare, no prefix) of payload_canonical
//! signature              = base64url( Ed25519( utf8("{payload_canonical}|{key_id}") ) )
//! ```
//!
//! The key_id is bound into the signed bytes, so a signature cannot be lifted
//! onto a different key. NOTE (documented signer behaviour): the envelope
//! metadata OUTSIDE `payload` — `kind`, `envelopeVersion`, `orgId`,
//! `exportedAt` — is NOT covered by the signature. Treat the signed payload as
//! the evidence; treat the envelope metadata as convenience labelling. The
//! payload itself carries `orgId` and period bounds, so the load-bearing facts
//! are all inside the signed bytes.
//!
//! Verification never panics on bad input — every failure is an `AuditStep`
//! with a stable reason code, mirroring the rest of the SDK.

use crate::canonical_json::{base64url_decode_strict, canonical_sort_keys};
use crate::hashing::sha256_hex;
use crate::keys::{KeyDirectory, KeyLookupResult};
use crate::types::{
    AuditReasonCode, AuditStep, AuditStepKind, AuditStepStatus, SDK_VERSION,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wire-compatible mirror of the platform envelope
/// (packages/sandbox-core/src/exports.ts `SignedExport<T>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedExport {
    /// "metering.export.v1" | "settlement.export.v1" (open for future kinds).
    pub kind: String,
    /// Envelope version — this verifier supports "export.v1".
    #[serde(rename = "envelopeVersion")]
    pub envelope_version: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
    /// ISO-8601. Also the instant the signing key is validity-checked against.
    #[serde(rename = "exportedAt")]
    pub exported_at: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: String,
    /// The summary as issued (metering / settlement summary / …).
    pub payload: Value,
    /// Transparency copy of the exact bytes that were hashed + signed.
    #[serde(rename = "payloadCanonical")]
    pub payload_canonical: String,
    /// sha256 hex of payload_canonical.
    #[serde(rename = "payloadCanonicalHash")]
    pub payload_canonical_hash: String,
    /// base64url Ed25519 signature over `"{payload_canonical}|{key_id}"`.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedExportAuditReport {
    pub status: AuditStepStatus,
    /// Envelope `kind` as declared (unsigned metadata — see module note).
    pub kind: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "exportedAt")]
    pub exported_at: String,
    /// ISO-8601 — when the audit ran.
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    pub steps: Vec<AuditStep>,
}

/// Verify a signed export offline against a key directory.
///
/// Steps (each an AuditStep; overall status is INVALID if any step is):
///   1. envelope         — envelope_version is "export.v1", algorithm
///                         "ed25519".
///   2. key_lookup       — key_id resolves in the directory and is inside its
///                         validity window (checked at `exported_at`), not
///                         revoked.
///   3. canonicalisation — re-canonicalising `payload` reproduces
///                         `payload_canonical` byte-for-byte, and its sha256
///                         matches `payload_canonical_hash`.
///   4. signature        — Ed25519 over `"{payload_canonical}|{key_id}"`
///                         verifies under the directory key.
///
/// The deeper content checks (does the metering re-project? does the
/// settlement reconcile?) remain the job of `verify_metering_projection` /
/// `verify_settlement_reconciliation` — deserialise `export.payload` into the
/// summary type and pass it on after this signature gate passes.
pub fn verify_signed_export(
    exp: &SignedExport,
    keys: &KeyDirectory,
) -> SignedExportAuditReport {
    let mut steps: Vec<AuditStep> = Vec::new();

    // ── 1. Envelope ──────────────────────────────────────────────────
    if exp.envelope_version != "export.v1" {
        steps.push(AuditStep {
            target: "export.envelopeVersion".to_string(),
            kind: AuditStepKind::Envelope,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::UnsupportedEnvelopeVersion),
            message: format!(
                "unsupported export envelope version {:?} (verifier supports \"export.v1\")",
                exp.envelope_version
            ),
            detail: None,
        });
    } else {
        steps.push(valid_step(
            "export.envelopeVersion",
            AuditStepKind::Envelope,
            "envelope version export.v1",
        ));
    }
    if exp.algorithm != "ed25519" {
        steps.push(AuditStep {
            target: "export.algorithm".to_string(),
            kind: AuditStepKind::Envelope,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::UnsupportedAlgorithm),
            message: format!("unsupported signature algorithm {:?}", exp.algorithm),
            detail: None,
        });
    } else {
        steps.push(valid_step(
            "export.algorithm",
            AuditStepKind::Envelope,
            "algorithm ed25519",
        ));
    }

    // ── 2. Key lookup (validity window anchored at exported_at) ───────
    let key = match keys.lookup(&exp.key_id, &exp.exported_at) {
        KeyLookupResult::Hit(k) => k,
        KeyLookupResult::Miss(reason) => {
            let (code, reason_str) = match reason {
                crate::keys::KeyMissReason::UnknownKeyId => {
                    (AuditReasonCode::UnknownKeyId, "UNKNOWN_KEY_ID")
                }
                crate::keys::KeyMissReason::OutsideValidityWindow => (
                    AuditReasonCode::KeyOutsideValidityWindow,
                    "KEY_OUTSIDE_VALIDITY_WINDOW",
                ),
                crate::keys::KeyMissReason::RevokedBeforeIssuance => (
                    AuditReasonCode::KeyRevokedBeforeIssuance,
                    "KEY_REVOKED_BEFORE_ISSUANCE",
                ),
            };
            steps.push(AuditStep {
                target: "export.keyId".to_string(),
                kind: AuditStepKind::KeyLookup,
                status: AuditStepStatus::Invalid,
                reason: Some(code),
                message: format!(
                    "signing key {:?} not usable at {}: {}",
                    exp.key_id, exp.exported_at, reason_str
                ),
                detail: None,
            });
            return finish(exp, steps);
        }
    };
    steps.push(valid_step(
        "export.keyId",
        AuditStepKind::KeyLookup,
        &format!(
            "key {:?} resolved and inside its validity window",
            exp.key_id
        ),
    ));

    // ── 3. Canonicalisation + hash transparency ───────────────────────
    let recomputed_canonical = canonical_sort_keys(&exp.payload);
    if recomputed_canonical != exp.payload_canonical {
        steps.push(AuditStep {
            target: "export.payloadCanonical".to_string(),
            kind: AuditStepKind::Canonicalisation,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::PayloadCanonicalMismatch),
            message:
                "re-canonicalising the payload does not reproduce payloadCanonical — the payload was modified after signing"
                    .to_string(),
            detail: None,
        });
        return finish(exp, steps);
    }
    steps.push(valid_step(
        "export.payloadCanonical",
        AuditStepKind::Canonicalisation,
        "payload re-canonicalises byte-for-byte",
    ));

    let recomputed_hash = sha256_hex(&recomputed_canonical);
    if recomputed_hash != exp.payload_canonical_hash {
        steps.push(AuditStep {
            target: "export.payloadCanonicalHash".to_string(),
            kind: AuditStepKind::Canonicalisation,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::ExportPayloadHashMismatch),
            message: "sha256(payloadCanonical) does not equal payloadCanonicalHash"
                .to_string(),
            detail: Some(serde_json::json!({
                "expected": recomputed_hash,
                "actual": exp.payload_canonical_hash,
            })),
        });
        return finish(exp, steps);
    }
    steps.push(valid_step(
        "export.payloadCanonicalHash",
        AuditStepKind::Canonicalisation,
        "payload hash matches",
    ));

    // ── 4. Signature over "{payload_canonical}|{key_id}" ──────────────
    let public_key_bytes = match base64url_decode_strict(&key.public_key) {
        Ok(b) => b,
        Err(_) => {
            steps.push(malformed_signature_step());
            return finish(exp, steps);
        }
    };
    let signature_bytes = match base64url_decode_strict(&exp.signature) {
        Ok(b) => b,
        Err(_) => {
            steps.push(malformed_signature_step());
            return finish(exp, steps);
        }
    };
    let message = format!("{}|{}", exp.payload_canonical, exp.key_id);
    // Mirror the TS Noble verifier's acceptance behaviour: wrong lengths,
    // non-curve public keys, and mauled signatures all yield `false` →
    // SIGNATURE_INVALID (never a panic). verify_strict matches the strict
    // acceptance set of @noble/ed25519 and pyca (CRYPTO-02).
    let ok = ed25519_verify_strict(&public_key_bytes, message.as_bytes(), &signature_bytes);
    if ok {
        steps.push(valid_step(
            "export.signature",
            AuditStepKind::Signature,
            "Ed25519 signature verifies under the directory key",
        ));
    } else {
        steps.push(AuditStep {
            target: "export.signature".to_string(),
            kind: AuditStepKind::Signature,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::SignatureInvalid),
            message: "Ed25519 signature does not verify — the export is not authentic"
                .to_string(),
            detail: None,
        });
    }
    finish(exp, steps)
}

fn ed25519_verify_strict(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&public_key[..32]);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature[..64]);
    let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key.verify_strict(message, &signature).is_ok()
}

fn malformed_signature_step() -> AuditStep {
    AuditStep {
        target: "export.signature".to_string(),
        kind: AuditStepKind::Signature,
        status: AuditStepStatus::Invalid,
        reason: Some(AuditReasonCode::SignatureMalformed),
        message: "signature or public key is not valid base64url".to_string(),
        detail: None,
    }
}

fn finish(exp: &SignedExport, steps: Vec<AuditStep>) -> SignedExportAuditReport {
    let status = if steps.iter().any(|s| s.status == AuditStepStatus::Invalid) {
        AuditStepStatus::Invalid
    } else {
        AuditStepStatus::Valid
    };
    SignedExportAuditReport {
        status,
        kind: exp.kind.clone(),
        org_id: exp.org_id.clone(),
        key_id: exp.key_id.clone(),
        exported_at: exp.exported_at.clone(),
        verified_at: chrono::Utc::now().to_rfc3339(),
        sdk_version: SDK_VERSION.to_string(),
        steps,
    }
}

fn valid_step(target: &str, kind: AuditStepKind, message: &str) -> AuditStep {
    AuditStep {
        target: target.to_string(),
        kind,
        status: AuditStepStatus::Valid,
        reason: None,
        message: message.to_string(),
        detail: None,
    }
}
