//! Settlement reconciliation audit.

use crate::hashing::settlement_idem_key;
use crate::types::{
    AuditReasonCode, AuditStep, AuditStepKind, AuditStepStatus, MeteringSummary,
    SettlementAuditReport, SettlementLine, SettlementSummary, SDK_VERSION,
};
use std::collections::HashMap;

const SHARE_PLACES: u32 = 6;

/// Re-derive every settlement line and assert equality.
pub fn verify_settlement_reconciliation(
    metering: &MeteringSummary,
    settlement: &SettlementSummary,
) -> SettlementAuditReport {
    let verified_at = chrono::Utc::now().to_rfc3339();
    let mut steps: Vec<AuditStep> = Vec::new();

    if settlement.org_id != metering.org_id {
        steps.push(AuditStep {
            target: "settlement.orgId".to_string(),
            kind: AuditStepKind::SettlementLine,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::SettlementOrgMismatch),
            message: format!(
                "settlement.orgId {:?} does not match metering.orgId {:?}",
                settlement.org_id, metering.org_id
            ),
            detail: None,
        });
    } else {
        steps.push(valid_step(
            "settlement.orgId",
            AuditStepKind::SettlementLine,
            "settlement orgId matches metering",
        ));
    }

    let meter_by_idem: HashMap<&str, &crate::types::MeterRecord> =
        metering.records.iter().map(|r| (r.idem_key.as_str(), r)).collect();

    let mut lines_by_meter: HashMap<&str, Vec<&SettlementLine>> = HashMap::new();
    for line in settlement.lines.iter() {
        lines_by_meter
            .entry(line.meter_record_idem_key.as_str())
            .or_default()
            .push(line);
    }

    // CRYPTO-04: recompute each meter's deterministic integer split exactly
    // (floor per share + residual reabsorbed into the largest-share line, ties
    // broken by the smaller partyRole) — the byte-for-byte mirror of the
    // platform's `splitGrossDeterministically` — and require exact-cent
    // equality per line below. No tolerance band.
    let mut expected_by_idx: HashMap<usize, i64> = HashMap::new();
    {
        let mut idx_by_meter: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, line) in settlement.lines.iter().enumerate() {
            idx_by_meter
                .entry(line.meter_record_idem_key.as_str())
                .or_default()
                .push(i);
        }
        for (meter_idem, idxs) in idx_by_meter.iter() {
            let gross = match settlement.meter_gross.get(*meter_idem) {
                Some(g) => *g,
                None => continue, // flagged per-line below
            };
            let shares: Vec<i128> = idxs
                .iter()
                .map(|&i| {
                    parse_decimal_to_scaled(&settlement.lines[i].share, SHARE_PLACES)
                        .unwrap_or(0)
                })
                .collect();
            let roles: Vec<&str> = idxs
                .iter()
                .map(|&i| settlement.lines[i].party_role.as_wire_str())
                .collect();
            let split = deterministic_split_cents(gross, &shares, &roles);
            for (k, &i) in idxs.iter().enumerate() {
                expected_by_idx.insert(i, split[k]);
            }
        }
    }

    let mut computed_gross: i64 = 0;
    let mut computed_net_to_tenant: i64 = 0;
    let mut computed_platform_fee: i64 = 0;

    for (i, line) in settlement.lines.iter().enumerate() {
        let _meter = match meter_by_idem.get(line.meter_record_idem_key.as_str()) {
            Some(m) => *m,
            None => {
                steps.push(AuditStep {
                    target: format!("settlement.lines[{i}].meterRecordIdemKey"),
                    kind: AuditStepKind::SettlementLine,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::SettlementLineForUnknownMeter),
                    message: format!(
                        "settlement line references meterRecordIdemKey {:?} not in metering",
                        line.meter_record_idem_key
                    ),
                    detail: None,
                });
                continue;
            }
        };

        let expected_idem = settlement_idem_key(
            &line.meter_record_idem_key,
            line.party_role.as_wire_str(),
            &line.ledger_account_code,
        );
        if line.idem_key != expected_idem {
            steps.push(AuditStep {
                target: format!("settlement.lines[{i}].idemKey"),
                kind: AuditStepKind::SettlementLine,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::SettlementIdemKeyMismatch),
                message:
                    "settlement-line idemKey does not equal sha256(meterIdemKey|partyRole|ledgerAccountCode)"
                        .to_string(),
                detail: Some(serde_json::json!({
                    "expected": expected_idem,
                    "actual": line.idem_key,
                })),
            });
        } else {
            steps.push(valid_step(
                &format!("settlement.lines[{i}].idemKey"),
                AuditStepKind::SettlementLine,
                "settlement idemKey matches reconstruction",
            ));
        }

        let gross = match settlement.meter_gross.get(&line.meter_record_idem_key) {
            Some(g) => *g,
            None => {
                steps.push(AuditStep {
                    target: format!(
                        "settlement.meterGross.{}",
                        line.meter_record_idem_key
                    ),
                    kind: AuditStepKind::SettlementLine,
                    status: AuditStepStatus::Invalid,
                    reason: Some(AuditReasonCode::SettlementLineForUnknownMeter),
                    message: format!(
                        "no gross amount for meterIdemKey {:?}",
                        line.meter_record_idem_key
                    ),
                    detail: None,
                });
                continue;
            }
        };

        // Validate the share decimal up front so malformed input surfaces a
        // clear step rather than silently scaling to zero.
        if parse_decimal_to_scaled(&line.share, SHARE_PLACES).is_err() {
            steps.push(AuditStep {
                target: format!("settlement.lines[{i}].share"),
                kind: AuditStepKind::SettlementLine,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::SettlementAmountMismatch),
                message: "share value is not a valid decimal".to_string(),
                detail: None,
            });
            continue;
        }
        // Exact-cent comparison against the precomputed deterministic split
        // (CRYPTO-04) — the largest-share line carries the residual exactly,
        // every other line is floor(gross * share). No tolerance band.
        let expected = expected_by_idx.get(&i).copied();
        if expected != Some(line.amount_cents) {
            steps.push(AuditStep {
                target: format!("settlement.lines[{i}].amountCents"),
                kind: AuditStepKind::SettlementLine,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::SettlementAmountMismatch),
                message:
                    "amountCents does not equal the deterministic integer split of grossCents by share"
                        .to_string(),
                detail: Some(serde_json::json!({
                    "expected": expected,
                    "actual": line.amount_cents,
                    "gross": gross,
                    "share": line.share,
                })),
            });
            continue;
        }
        steps.push(valid_step(
            &format!("settlement.lines[{i}].amountCents"),
            AuditStepKind::SettlementLine,
            &format!(
                "amountCents={} matches deterministic split of gross={} by share={}",
                line.amount_cents, gross, line.share
            ),
        ));
        computed_gross += line.amount_cents;
        match line.party_role {
            crate::types::SettlementPartyRole::Tenant => {
                computed_net_to_tenant += line.amount_cents
            }
            crate::types::SettlementPartyRole::Platform => {
                computed_platform_fee += line.amount_cents
            }
            _ => {}
        }
    }

    // Per-meter share-sum check.
    for (meter_idem, group) in lines_by_meter.iter() {
        let sum_scaled: i128 = group
            .iter()
            .map(|l| parse_decimal_to_scaled(&l.share, SHARE_PLACES).unwrap_or(0))
            .sum();
        if sum_scaled != 10_i128.pow(SHARE_PLACES) {
            steps.push(AuditStep {
                target: format!("settlement.lines[meter={meter_idem}].share"),
                kind: AuditStepKind::SettlementLine,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::SettlementShareSumNotOne),
                message: format!(
                    "shares for meter {meter_idem:?} sum to {}, not 1.000000",
                    format_scaled_decimal(sum_scaled, SHARE_PLACES)
                ),
                detail: None,
            });
        } else {
            steps.push(valid_step(
                &format!("settlement.lines[meter={meter_idem}].share"),
                AuditStepKind::SettlementLine,
                &format!("shares for meter {meter_idem:?} sum to 1.000000"),
            ));
        }
    }

    if let Some(totals) = &settlement.totals {
        push_total_check(
            &mut steps,
            "grossCents",
            totals.gross_cents,
            computed_gross,
        );
        push_total_check(
            &mut steps,
            "netToTenantCents",
            totals.net_to_tenant_cents,
            computed_net_to_tenant,
        );
        push_total_check(
            &mut steps,
            "platformFeeCents",
            totals.platform_fee_cents,
            computed_platform_fee,
        );
    }

    let any_invalid = steps.iter().any(|s| s.status == AuditStepStatus::Invalid);
    SettlementAuditReport {
        status: if any_invalid {
            AuditStepStatus::Invalid
        } else {
            AuditStepStatus::Valid
        },
        verified_at,
        sdk_version: SDK_VERSION.to_string(),
        meter_record_count: metering.records.len(),
        settlement_line_count: settlement.lines.len(),
        steps,
    }
}

fn push_total_check(steps: &mut Vec<AuditStep>, label: &str, claimed: i64, computed: i64) {
    if claimed != computed {
        steps.push(AuditStep {
            target: format!("settlement.totals.{label}"),
            kind: AuditStepKind::SettlementTotal,
            status: AuditStepStatus::Invalid,
            reason: Some(AuditReasonCode::SettlementTotalMismatch),
            message: format!(
                "claimed {label}={claimed} does not match recomputed {computed}"
            ),
            detail: None,
        });
    } else {
        steps.push(AuditStep {
            target: format!("settlement.totals.{label}"),
            kind: AuditStepKind::SettlementTotal,
            status: AuditStepStatus::Valid,
            reason: None,
            message: format!("{label}={claimed} reconciles"),
            detail: None,
        });
    }
}

/// Mirror of the platform's `splitGrossDeterministically`
/// (apps/api settlementService.ts). Floors each share's slice as
/// `floor(gross * shareScaled / 1_000_000)` and reabsorbs the residual
/// (`gross − Σ floors`) into the largest-share line, ties broken by the
/// smaller partyRole (lexical). Deterministic and sums to exactly `gross`.
fn deterministic_split_cents(
    gross: i64,
    shares_scaled: &[i128],
    party_roles: &[&str],
) -> Vec<i64> {
    let scale = 10_i128.pow(SHARE_PLACES);
    let mut floors: Vec<i64> = shares_scaled
        .iter()
        .map(|&s| ((gross as i128 * s) / scale) as i64)
        .collect();
    let sum: i64 = floors.iter().sum();
    let remainder = gross - sum;
    if remainder != 0 && !floors.is_empty() {
        let mut target = 0usize;
        for (i, &s) in shares_scaled.iter().enumerate().skip(1) {
            if s > shares_scaled[target]
                || (s == shares_scaled[target] && party_roles[i] < party_roles[target])
            {
                target = i;
            }
        }
        floors[target] += remainder;
    }
    floors
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
