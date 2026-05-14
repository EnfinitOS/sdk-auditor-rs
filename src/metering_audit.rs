//! Metering re-projection audit. Mirrors the TS/Py meterAudit.

use crate::hashing::sha256_hex;
use crate::types::{
    AuditReasonCode, AuditStep, AuditStepKind, AuditStepStatus, MeterUnitType,
    MeteringSummary, ProjectionAuditReport, ProofRecord, SDK_VERSION,
};
use std::collections::HashMap;

const DECIMAL_PLACES: u32 = 6;

/// Re-project every meter record from the source proof receipt and
/// assert equality. The pack is the source-of-truth; the summary is
/// candidate-under-audit.
pub fn verify_metering_projection(
    proof_records: &[ProofRecord],
    metering: &MeteringSummary,
    pack_org_id: Option<&str>,
) -> ProjectionAuditReport {
    let verified_at = chrono::Utc::now().to_rfc3339();
    let mut steps: Vec<AuditStep> = Vec::new();

    let mut proof_by_receipt_id: HashMap<&str, &ProofRecord> = HashMap::new();
    for r in proof_records {
        proof_by_receipt_id.insert(&r.payload.receipt_id, r);
    }

    // 1. Org parity.
    if let Some(org) = pack_org_id {
        if metering.org_id != org {
            steps.push(AuditStep {
                target: "metering.orgId".to_string(),
                kind: AuditStepKind::MeterProjection,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::MeterOrgMismatch),
                message: format!(
                    "metering.orgId {:?} does not match pack.orgId {:?}",
                    metering.org_id, org
                ),
                detail: None,
            });
        } else {
            steps.push(valid_step(
                "metering.orgId",
                AuditStepKind::MeterProjection,
                "metering summary orgId matches pack",
            ));
        }
    }

    // 2..4 — walk every record.
    let mut computed_totals: HashMap<String, i128> = HashMap::new();
    for (i, m) in metering.records.iter().enumerate() {
        let proof = match proof_by_receipt_id.get(m.proof_receipt_id.as_str()) {
            Some(p) => p,
            None => {
                steps.push(AuditStep {
                    target: format!("metering.records[{i}].proofReceiptId"),
                    kind: AuditStepKind::MeterProjection,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::MeterRecordForUnknownProof),
                    message: format!(
                        "meter record references proofReceiptId {:?} that is not in \
                         the proof pack",
                        m.proof_receipt_id
                    ),
                    detail: None,
                });
                continue;
            }
        };

        // 3. idemKey reconstruction.
        let unit_type_str = m.unit_type.as_wire_str();
        let expected_idem =
            sha256_hex(&format!("{}|{}", m.proof_receipt_id, unit_type_str));
        if expected_idem != m.idem_key {
            steps.push(AuditStep {
                target: format!("metering.records[{i}].idemKey"),
                kind: AuditStepKind::MeterProjection,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::MeterIdemKeyMismatch),
                message: "idemKey on meter record does not equal sha256(proofReceiptId|unitType)"
                    .to_string(),
                detail: Some(serde_json::json!({
                    "expected": expected_idem,
                    "actual": m.idem_key,
                })),
            });
        } else {
            steps.push(valid_step(
                &format!("metering.records[{i}].idemKey"),
                AuditStepKind::MeterProjection,
                "idemKey matches sha256(proofReceiptId|unitType)",
            ));
        }

        // 4. unitCount reconstruction.
        let weight_scaled = match parse_decimal_to_scaled(&m.weight, DECIMAL_PLACES) {
            Ok(v) => v,
            Err(_) => {
                steps.push(AuditStep {
                    target: format!("metering.records[{i}].weight"),
                    kind: AuditStepKind::MeterProjection,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::MeterUnitCountMismatch),
                    message: "weight value is not a valid decimal".to_string(),
                    detail: None,
                });
                continue;
            }
        };
        let expected = match project_unit_count(proof.payload.dwell_ms, weight_scaled, m.unit_type) {
            Some(v) => v,
            None => {
                steps.push(AuditStep {
                    target: format!("metering.records[{i}].unitCount"),
                    kind: AuditStepKind::MeterProjection,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::MeterUnitCountMismatch),
                    message: format!(
                        "unit type {:?} has no known projection — SDK build is older \
                         than the platform's policy table",
                        m.unit_type
                    ),
                    detail: None,
                });
                continue;
            }
        };
        let actual_scaled = match parse_decimal_to_scaled(&m.unit_count, DECIMAL_PLACES) {
            Ok(v) => v,
            Err(_) => {
                steps.push(AuditStep {
                    target: format!("metering.records[{i}].unitCount"),
                    kind: AuditStepKind::MeterProjection,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::MeterUnitCountMismatch),
                    message: "unitCount value is not a valid decimal".to_string(),
                    detail: None,
                });
                continue;
            }
        };
        if actual_scaled != expected {
            steps.push(AuditStep {
                target: format!("metering.records[{i}].unitCount"),
                kind: AuditStepKind::MeterProjection,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::MeterUnitCountMismatch),
                message: format!(
                    "unitCount does not match deterministic re-projection from \
                     proof.dwellMs={} weight={} unitType={:?}",
                    proof.payload.dwell_ms, m.weight, m.unit_type
                ),
                detail: Some(serde_json::json!({
                    "expected": format_scaled_decimal(expected, DECIMAL_PLACES),
                    "actual": m.unit_count,
                })),
            });
        } else {
            steps.push(valid_step(
                &format!("metering.records[{i}].unitCount"),
                AuditStepKind::MeterProjection,
                "unitCount re-projects exactly from proof",
            ));
        }

        *computed_totals.entry(unit_type_str.to_string()).or_insert(0) += expected;
    }

    // 5. Totals.
    if let Some(totals) = &metering.totals {
        for (unit_type, claimed) in totals.iter() {
            let computed = *computed_totals.get(unit_type).unwrap_or(&0);
            let claimed_scaled = match parse_decimal_to_scaled(claimed, DECIMAL_PLACES) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if claimed_scaled != computed {
                steps.push(AuditStep {
                    target: format!("metering.totals.{unit_type}"),
                    kind: AuditStepKind::MeterTotal,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::MeterTotalMismatch),
                    message: format!(
                        "claimed total for {unit_type} does not match sum of per-record \
                         projections"
                    ),
                    detail: Some(serde_json::json!({
                        "expected": format_scaled_decimal(computed, DECIMAL_PLACES),
                        "actual": claimed,
                    })),
                });
            } else {
                steps.push(valid_step(
                    &format!("metering.totals.{unit_type}"),
                    AuditStepKind::MeterTotal,
                    &format!("claimed total for {unit_type} matches sum of records"),
                ));
            }
        }
    }

    let any_invalid = steps.iter().any(|s| s.status == AuditStepStatus::Invalid);
    ProjectionAuditReport {
        status: if any_invalid {
            AuditStepStatus::Invalid
        } else {
            AuditStepStatus::Valid
        },
        verified_at,
        sdk_version: SDK_VERSION.to_string(),
        proof_record_count: proof_records.len(),
        meter_record_count: metering.records.len(),
        steps,
    }
}

fn project_unit_count(
    dwell_ms: i64,
    weight_scaled: i128,
    unit_type: MeterUnitType,
) -> Option<i128> {
    let factor: i128 = 10_i128.pow(DECIMAL_PLACES);
    match unit_type {
        MeterUnitType::DwellSeconds
        | MeterUnitType::AttentionSeconds
        | MeterUnitType::OccupancyWeightedExposure => {
            let dwell_scaled: i128 = (dwell_ms as i128 * factor) / 1000;
            Some((dwell_scaled * weight_scaled) / factor)
        }
        MeterUnitType::ImpressionInPlace => Some(weight_scaled),
        MeterUnitType::CompliantDeliveryMinute => {
            let dwell_scaled: i128 = (dwell_ms as i128 * factor) / 60_000;
            Some((dwell_scaled * weight_scaled) / factor)
        }
        MeterUnitType::Custom => None,
    }
}

fn parse_decimal_to_scaled(s: &str, places: u32) -> Result<i128, ()> {
    let s = s.trim();
    let (sign, body) = if let Some(rest) = s.strip_prefix('-') {
        (-1i128, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (1, rest)
    } else {
        (1, s)
    };
    let (int_part, frac_part) = match body.split_once('.') {
        Some((a, b)) => (a, b),
        None => (body, ""),
    };
    if int_part.is_empty() || !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    if !frac_part.is_empty() && !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    let mut padded = String::from(frac_part);
    while padded.len() < places as usize {
        padded.push('0');
    }
    padded.truncate(places as usize);
    let combined = format!("{int_part}{padded}");
    combined.parse::<i128>().map(|n| sign * n).map_err(|_| ())
}

fn format_scaled_decimal(n: i128, places: u32) -> String {
    let (sign, abs_n) = if n < 0 { ("-", -n) } else { ("", n) };
    let mut s = abs_n.to_string();
    while s.len() <= places as usize {
        s.insert(0, '0');
    }
    let split = s.len() - places as usize;
    format!("{sign}{}.{}", &s[..split], &s[split..])
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
