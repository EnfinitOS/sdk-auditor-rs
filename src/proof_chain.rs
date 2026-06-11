//! Proof-chain walking + continuity verification.

use crate::types::{
    AuditReasonCode, AuditStep, AuditStepKind, AuditStepStatus, ChainAuditReport,
    ProofRecord, SDK_VERSION,
};
use chrono::DateTime;

/// Walk records in array order; report each link's status.
///
/// Invariants:
///   1. records[0].before_hash MUST be None.
///   2. records[i].before_hash MUST equal records[i-1].after_hash.
///   3. issued_at MUST be non-decreasing along the chain.
pub fn verify_proof_chain(records: &[ProofRecord]) -> ChainAuditReport {
    let verified_at = chrono::Utc::now().to_rfc3339();
    let mut steps: Vec<AuditStep> = Vec::new();

    if records.is_empty() {
        return ChainAuditReport {
            status: AuditStepStatus::Invalid,
            verified_at,
            sdk_version: SDK_VERSION.to_string(),
            record_count: 0,
            steps: vec![AuditStep {
                target: "records".to_string(),
                kind: AuditStepKind::ChainLink,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::MalformedPack),
                message: "proof chain is empty — cannot audit a zero-record pack"
                    .to_string(),
                detail: None,
            }],
        };
    }

    // 1. Genesis check.
    let first = &records[0];
    if first.before_hash.is_some() {
        steps.push(AuditStep {
            target: "records[0].beforeHash".to_string(),
            kind: AuditStepKind::ChainLink,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::GenesisBeforeHashNotNull),
            message: "first record carries a non-null beforeHash".to_string(),
            detail: Some(serde_json::json!({
                "beforeHash": first.before_hash,
            })),
        });
    } else {
        steps.push(valid_step(
            "records[0].beforeHash",
            "genesis record has null beforeHash, as expected",
        ));
    }

    // 2. Continuity + 3. ordering.
    let mut prev_issued_at_ms: Option<i64> = parse_iso(&first.payload.issued_at);
    for i in 1..records.len() {
        let curr = &records[i];
        let prev = &records[i - 1];

        match &curr.before_hash {
            None => {
                steps.push(AuditStep {
                    target: format!("records[{i}].beforeHash"),
                    kind: AuditStepKind::ChainLink,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::GenesisBeforeHashNotNull),
                    message: format!(
                        "non-genesis record at index {i} carries a null beforeHash"
                    ),
                    detail: None,
                });
            }
            Some(curr_before) if curr_before != &prev.after_hash => {
                steps.push(AuditStep {
                    target: format!("records[{i}].beforeHash"),
                    kind: AuditStepKind::ChainLink,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::ChainLinkMismatch),
                    message: format!(
                        "record[{i}].beforeHash does not equal record[{}].afterHash",
                        i - 1
                    ),
                    detail: Some(serde_json::json!({
                        "expected": prev.after_hash,
                        "actual": curr_before,
                    })),
                });
            }
            _ => {
                steps.push(valid_step(
                    &format!("records[{i}].beforeHash"),
                    &format!("record[{i}] correctly chains off record[{}]", i - 1),
                ));
            }
        }

        let curr_ms = parse_iso(&curr.payload.issued_at);
        if let (Some(curr_ms), Some(prev_ms)) = (curr_ms, prev_issued_at_ms) {
            if curr_ms < prev_ms {
                steps.push(AuditStep {
                    target: format!("records[{i}].payload.issuedAt"),
                    kind: AuditStepKind::ChainLink,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::ChainOutOfOrder),
                    message: format!(
                        "record[{i}].issuedAt is earlier than record[{}].issuedAt",
                        i - 1
                    ),
                    detail: None,
                });
            }
        }
        prev_issued_at_ms = curr_ms;
    }

    // 4. Nonce uniqueness (CRYPTO-07). The platform enforces
    // @@unique([orgId, nonce]); a repeated nonce inside a pack means a replayed
    // or duplicated receipt — which the hash-chain walk alone won't catch if a
    // duplicate is spliced in with a fresh beforeHash.
    let mut seen_nonce: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    let mut nonce_reuse = 0usize;
    for (i, rec) in records.iter().enumerate() {
        let nonce = rec.payload.nonce.as_str();
        if let Some(&first_idx) = seen_nonce.get(nonce) {
            nonce_reuse += 1;
            steps.push(AuditStep {
                target: format!("records[{i}].payload.nonce"),
                kind: AuditStepKind::ChainLink,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::ChainNonceReused),
                message: format!(
                    "record[{i}] reuses a nonce first seen at record[{first_idx}] — per-org nonce uniqueness is enforced; a repeat indicates a replayed or duplicated receipt"
                ),
                detail: Some(serde_json::json!({
                    "firstIndex": first_idx,
                    "duplicateIndex": i,
                })),
            });
        } else {
            seen_nonce.insert(nonce, i);
        }
    }
    if nonce_reuse == 0 {
        steps.push(valid_step(
            "records[].payload.nonce",
            &format!("all {} record nonces are unique", records.len()),
        ));
    }

    let any_invalid = steps.iter().any(|s| s.status == AuditStepStatus::Invalid);
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

fn valid_step(target: &str, message: &str) -> AuditStep {
    AuditStep {
        target: target.to_string(),
        kind: AuditStepKind::ChainLink,
        status: AuditStepStatus::Valid,
        reason: None,
        message: message.to_string(),
        detail: None,
    }
}

fn parse_iso(iso: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(iso).ok().map(|d| d.timestamp_millis())
}
