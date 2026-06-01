//! Proof pack parsing + per-record signature verification.

use crate::canonical_json::{
    base64url_decode, canonicalise_proof_payload, canonicalise_proof_signing_input,
};
use crate::hashing::{constant_time_hex_equal, sha256_hex};
use crate::keys::{KeyDirectory, KeyLookupResult, KeyMissReason};
use crate::types::{
    AuditReasonCode, AuditStep, AuditStepKind, AuditStepStatus, ProofRecord,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify a single proof record. Returns the audit steps generated:
///   1. canonicalisation parity
///   2. afterHash parity
///   3. key lookup
///   4. Ed25519 signature
pub fn verify_proof_record(
    record: &ProofRecord,
    record_index: usize,
    keys: &KeyDirectory,
) -> Vec<AuditStep> {
    let mut steps: Vec<AuditStep> = Vec::with_capacity(4);

    // 1. Canonicalisation parity.
    let local_canonical = canonicalise_proof_payload(&record.payload);
    if local_canonical != record.payload_canonical {
        steps.push(AuditStep {
            target: format!("record[{record_index}].payloadCanonical"),
            kind: AuditStepKind::Canonicalisation,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::PayloadCanonicalMismatch),
            message:
                "canonical payload bytes do not match — encoder version skew or tampering"
                    .to_string(),
            detail: Some(serde_json::json!({
                "expected": &record.payload_canonical[..256.min(record.payload_canonical.len())],
                "actual": &local_canonical[..256.min(local_canonical.len())],
            })),
        });
    } else {
        steps.push(valid_step(
            format!("record[{record_index}].payloadCanonical"),
            AuditStepKind::Canonicalisation,
            "canonical payload bytes match",
        ));
    }

    // 2. afterHash parity.
    let expected_after_hash = sha256_hex(&local_canonical);
    if !constant_time_hex_equal(&expected_after_hash, &record.after_hash) {
        steps.push(AuditStep {
            target: format!("record[{record_index}].afterHash"),
            kind: AuditStepKind::Canonicalisation,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::AfterHashMismatch),
            message: "record afterHash does not equal sha256(payloadCanonical)"
                .to_string(),
            detail: Some(serde_json::json!({
                "expected": expected_after_hash,
                "actual": record.after_hash,
            })),
        });
    } else {
        steps.push(valid_step(
            format!("record[{record_index}].afterHash"),
            AuditStepKind::Canonicalisation,
            "afterHash equals sha256(payloadCanonical)",
        ));
    }

    // 3. Key lookup.
    let key = match keys.lookup(&record.key_id, &record.payload.issued_at) {
        KeyLookupResult::Hit(k) => k,
        KeyLookupResult::Miss(reason) => {
            let (code, message) = miss_reason_to_audit(reason, &record.key_id);
            steps.push(AuditStep {
                target: format!("record[{record_index}].keyId"),
                kind: AuditStepKind::KeyLookup,
                status: AuditStepStatus::Invalid,
                reason: Some(code),
                message,
                detail: Some(serde_json::json!({
                    "keyId": record.key_id,
                    "issuedAt": record.payload.issued_at,
                })),
            });
            return steps;
        }
    };
    steps.push(valid_step(
        format!("record[{record_index}].keyId"),
        AuditStepKind::KeyLookup,
        &format!("key {:?} resolved and valid for issuedAt", record.key_id),
    ));

    // 4. Signature verification.
    let signature_bytes = match base64url_decode(&record.signature) {
        Ok(b) => b,
        Err(_) => {
            steps.push(AuditStep {
                target: format!("record[{record_index}].signature"),
                kind: AuditStepKind::Signature,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::SignatureMalformed),
                message: "signature base64url decoding failed".to_string(),
                detail: None,
            });
            return steps;
        }
    };
    let public_bytes = match base64url_decode(&key.public_key) {
        Ok(b) => b,
        Err(_) => {
            steps.push(AuditStep {
                target: format!("record[{record_index}].signature"),
                kind: AuditStepKind::Signature,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::SignatureMalformed),
                message: "public key base64url decoding failed".to_string(),
                detail: None,
            });
            return steps;
        }
    };
    if signature_bytes.len() != 64 || public_bytes.len() != 32 {
        steps.push(AuditStep {
            target: format!("record[{record_index}].signature"),
            kind: AuditStepKind::Signature,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::SignatureMalformed),
            message: format!(
                "expected 64-byte signature / 32-byte public key, got {} / {}",
                signature_bytes.len(),
                public_bytes.len()
            ),
            detail: None,
        });
        return steps;
    }

    let signing_input =
        canonicalise_proof_signing_input(&record.payload, &record.key_id);

    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&public_bytes[..32]);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes[..64]);

    let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
        Ok(k) => k,
        Err(_) => {
            steps.push(AuditStep {
                target: format!("record[{record_index}].signature"),
                kind: AuditStepKind::Signature,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::SignatureMalformed),
                message: "public key was not a valid Ed25519 point".to_string(),
                detail: None,
            });
            return steps;
        }
    };
    let signature = Signature::from_bytes(&sig_arr);

    let ok = verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .is_ok();
    if ok {
        steps.push(valid_step(
            format!("record[{record_index}].signature"),
            AuditStepKind::Signature,
            "Ed25519 signature verifies against the declared key",
        ));
    } else {
        steps.push(AuditStep {
            target: format!("record[{record_index}].signature"),
            kind: AuditStepKind::Signature,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::SignatureInvalid),
            message: "Ed25519 signature did NOT verify — record has been tampered with"
                .to_string(),
            detail: None,
        });
    }

    steps
}

fn miss_reason_to_audit(
    reason: KeyMissReason,
    key_id: &str,
) -> (AuditReasonCode, String) {
    match reason {
        KeyMissReason::UnknownKeyId => (
            AuditReasonCode::UnknownKeyId,
            format!("keyId {key_id:?} is not in the verification key directory"),
        ),
        KeyMissReason::OutsideValidityWindow => (
            AuditReasonCode::KeyOutsideValidityWindow,
            format!(
                "keyId {key_id:?} is outside its declared validity window for the \
                 record's issuedAt"
            ),
        ),
        KeyMissReason::RevokedBeforeIssuance => (
            AuditReasonCode::KeyRevokedBeforeIssuance,
            format!(
                "keyId {key_id:?} was revoked before the record's issuedAt — the \
                 record cannot be trusted"
            ),
        ),
    }
}

fn valid_step(target: String, kind: AuditStepKind, message: &str) -> AuditStep {
    AuditStep {
        target,
        kind,
        status: AuditStepStatus::Valid,
        reason: None,
        message: message.to_string(),
        detail: None,
    }
}
