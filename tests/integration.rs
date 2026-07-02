//! Integration tests for the Rust auditor.
//!
//! Builds proof packs with a fresh Ed25519 key (via ed25519-dalek
//! signing) and verifies them through the public Auditor API. Each
//! test mirrors a TS/Py counterpart so the three SDKs stay in sync.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use enfinitos_auditor::{
    AuditBundle, AuditStepStatus, Auditor, MeterRecord, MeterStatus, MeterUnitType,
    MeteringSummary, ProofReceiptPayload, ProofRecord, SettlementLine,
    SettlementPartyRole, SettlementStatus, SettlementSummary, SettlementTotals,
    SignedProofPack, VerificationKey,
};
use enfinitos_auditor::canonical_json::{
    base64url_encode, canonicalise_proof_payload, canonicalise_proof_signing_input,
};
use enfinitos_auditor::hashing::{
    meter_idem_key, settlement_idem_key, settlement_idem_key_v1, sha256_hex,
};
use rand_compat::OsRng;
use std::collections::BTreeMap;

mod rand_compat {
    // Tiny shim so we don't pull a full rand_core feature flag dance —
    // ed25519-dalek expects a CryptoRng + RngCore. We use the OS RNG.
    pub use rand_core::OsRng;
}

struct Fixture {
    signing_key: SigningKey,
    key_id: String,
    verification_key: VerificationKey,
}

fn make_key() -> Fixture {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying: VerifyingKey = signing_key.verifying_key();
    let key_id = format!("fixture_key_{}", hex_short());
    let verification_key = VerificationKey {
        key_id: key_id.clone(),
        algorithm: "ed25519".to_string(),
        public_key: base64url_encode(verifying.as_bytes()),
        not_before: "2020-01-01T00:00:00.000Z".to_string(),
        not_after: None,
        revoked_at: None,
        purpose: Some("test_fixture".to_string()),
    };
    Fixture {
        signing_key,
        key_id,
        verification_key,
    }
}

fn hex_short() -> String {
    use sha2::{Digest, Sha256};
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let h = Sha256::digest(nonce.to_le_bytes());
    let mut s = String::new();
    for b in &h.as_slice()[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn sign_record(
    payload: ProofReceiptPayload,
    fx: &Fixture,
    before_hash: Option<String>,
) -> ProofRecord {
    let canonical = canonicalise_proof_payload(&payload);
    let signing_input = canonicalise_proof_signing_input(&payload, &fx.key_id);
    let signature = fx.signing_key.sign(signing_input.as_bytes());
    let after_hash = sha256_hex(&canonical);
    ProofRecord {
        payload,
        key_id: fx.key_id.clone(),
        algorithm: "ed25519".to_string(),
        signature: base64url_encode(&signature.to_bytes()),
        payload_canonical: canonical,
        before_hash,
        after_hash,
    }
}

fn make_pack(fx: &Fixture) -> SignedProofPack {
    let payload = ProofReceiptPayload {
        version: "1".to_string(),
        receipt_id: "rec_001".to_string(),
        correlation_id: None,
        spatial_anchor_id: "anchor_A".to_string(),
        spatial_placement_id: Some("place_A".to_string()),
        issued_at: "2026-04-01T12:00:00.000Z".to_string(),
        rendered_at: "2026-04-01T11:59:59.000Z".to_string(),
        dwell_ms: 3500,
        nonce: "n0001".to_string(),
        witness: None,
    };
    let record = sign_record(payload, fx, None);
    SignedProofPack {
        envelope_version: "envelope.v1".to_string(),
        issued_at: "2026-04-01T12:00:00.500Z".to_string(),
        org_id: "org_test".to_string(),
        pack_id: "pack_001".to_string(),
        label: None,
        records: vec![record],
        metering: None,
        settlement: None,
    }
}

fn make_multi_pack(fx: &Fixture, count: usize) -> SignedProofPack {
    make_chained_pack(fx, count, None, 0)
}

/// Like `make_multi_pack`, but seeds `records[0].before_hash` with
/// `prior_after_hash` — pass the previous pack's tail afterHash to build
/// the SECOND pack of a cross-pack chain (mirrors the platform's
/// `sealProofPack` threading `previousAfterHash` —
/// packages/sandbox-core/src/tenantState.ts). `start` offsets receipt
/// ids / nonces / timestamps so two packs don't collide.
fn make_chained_pack(
    fx: &Fixture,
    count: usize,
    prior_after_hash: Option<String>,
    start: usize,
) -> SignedProofPack {
    let mut records: Vec<ProofRecord> = Vec::new();
    for i in 0..count {
        let n = start + i;
        let payload = ProofReceiptPayload {
            version: "1".to_string(),
            receipt_id: format!("rec_{:03}", n),
            correlation_id: None,
            spatial_anchor_id: format!("anchor_{}", n % 3),
            spatial_placement_id: None,
            issued_at: format!("2026-04-01T12:{:02}:00.000Z", n),
            rendered_at: format!("2026-04-01T11:59:{:02}.000Z", n),
            dwell_ms: 1000 + (n as i64) * 250,
            nonce: format!("nonce_{}", n),
            witness: None,
        };
        let before = if i == 0 {
            prior_after_hash.clone()
        } else {
            Some(records[i - 1].after_hash.clone())
        };
        records.push(sign_record(payload, fx, before));
    }
    SignedProofPack {
        envelope_version: "envelope.v1".to_string(),
        issued_at: "2026-04-01T13:00:00.000Z".to_string(),
        org_id: "org_test".to_string(),
        pack_id: if start == 0 {
            "pack_multi".to_string()
        } else {
            format!("pack_multi_{start}")
        },
        label: None,
        records,
        metering: None,
        settlement: None,
    }
}

fn make_metering(pack: &SignedProofPack) -> MeteringSummary {
    let factor: i128 = 10_i128.pow(6);
    let mut total: i128 = 0;
    let mut records: Vec<MeterRecord> = Vec::new();
    for r in pack.records.iter() {
        let unit_scaled: i128 = (r.payload.dwell_ms as i128 * factor) / 1000;
        total += unit_scaled;
        records.push(MeterRecord {
            idem_key: meter_idem_key(&r.payload.receipt_id, "DWELL_SECONDS"),
            proof_receipt_id: r.payload.receipt_id.clone(),
            unit_type: MeterUnitType::DwellSeconds,
            unit_count: format_dec(unit_scaled, 6),
            weight: "1.000000".to_string(),
            spatial_anchor_id: r.payload.spatial_anchor_id.clone(),
            spatial_placement_id: r.payload.spatial_placement_id.clone(),
            observed_at: r.payload.rendered_at.clone(),
            status: MeterStatus::Projected,
        });
    }
    let mut totals: BTreeMap<String, String> = BTreeMap::new();
    totals.insert("DWELL_SECONDS".to_string(), format_dec(total, 6));
    totals.insert("IMPRESSION_IN_PLACE".to_string(), "0.000000".to_string());
    totals.insert("ATTENTION_SECONDS".to_string(), "0.000000".to_string());
    totals.insert(
        "OCCUPANCY_WEIGHTED_EXPOSURE".to_string(),
        "0.000000".to_string(),
    );
    totals.insert(
        "COMPLIANT_DELIVERY_MINUTE".to_string(),
        "0.000000".to_string(),
    );
    totals.insert("CUSTOM".to_string(), "0.000000".to_string());
    MeteringSummary {
        schema_version: "metering.v1".to_string(),
        org_id: pack.org_id.clone(),
        period_start: pack.records[0].payload.issued_at.clone(),
        period_end: pack.records[pack.records.len() - 1]
            .payload
            .issued_at
            .clone(),
        records,
        totals: Some(totals),
    }
}

fn make_settlement(metering: &MeteringSummary) -> SettlementSummary {
    let mut meter_gross: BTreeMap<String, i64> = BTreeMap::new();
    let mut lines: Vec<SettlementLine> = Vec::new();
    for m in metering.records.iter() {
        let seconds: i64 = parse_dec_int(&m.unit_count, 6);
        let gross = seconds * 100;
        meter_gross.insert(m.idem_key.clone(), gross);
        lines.push(SettlementLine {
            idem_key: settlement_idem_key(&m.idem_key, "TENANT", "SPATIAL_REVENUE_GROSS"),
            meter_record_idem_key: m.idem_key.clone(),
            party_role: SettlementPartyRole::Tenant,
            share: "1.000000".to_string(),
            ledger_account_code: "SPATIAL_REVENUE_GROSS".to_string(),
            amount_cents: gross,
            currency: "USD".to_string(),
            status: SettlementStatus::Projected,
        });
    }
    let total: i64 = lines.iter().map(|l| l.amount_cents).sum();
    SettlementSummary {
        schema_version: "settlement.v2".to_string(),
        org_id: metering.org_id.clone(),
        period_start: metering.period_start.clone(),
        period_end: metering.period_end.clone(),
        currency: "USD".to_string(),
        meter_gross,
        lines,
        totals: Some(SettlementTotals {
            gross_cents: total,
            net_to_tenant_cents: total,
            platform_fee_cents: 0,
        }),
    }
}

fn parse_dec_int(s: &str, _places: u32) -> i64 {
    let (int_part, _frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    int_part.parse::<i64>().unwrap_or(0)
}

fn format_dec(n: i128, places: u32) -> String {
    let abs = n.abs();
    let mut s = abs.to_string();
    while s.len() <= places as usize {
        s.insert(0, '0');
    }
    let split = s.len() - places as usize;
    let sign = if n < 0 { "-" } else { "" };
    format!("{sign}{}.{}", &s[..split], &s[split..])
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn verify_proof_pack_valid_honest_pack() {
    let fx = make_key();
    let pack = make_pack(&fx);
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let report = auditor.verify_proof_pack(&pack);
    assert_eq!(report.status, AuditStepStatus::Valid);
    assert_eq!(report.keys_snapshot.key_ids, vec![fx.key_id.clone()]);
}

#[test]
fn verify_proof_pack_invalid_for_tampered_payload() {
    let fx = make_key();
    let mut pack = make_pack(&fx);
    pack.records[0].payload.dwell_ms = 99999;
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let report = auditor.verify_proof_pack(&pack);
    assert_eq!(report.status, AuditStepStatus::Invalid);
}

#[test]
fn verify_all_full_pipeline_reconciles() {
    let fx = make_key();
    let pack = make_multi_pack(&fx, 3);
    let metering = make_metering(&pack);
    let settlement = make_settlement(&metering);
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let bundle = AuditBundle {
        pack,
        metering: Some(metering),
        settlement: Some(settlement),
        prior_after_hash: None,
    };
    let full = auditor.verify_all(&bundle);
    assert_eq!(full.status, AuditStepStatus::Valid);
    assert_eq!(full.pack.status, AuditStepStatus::Valid);
    assert_eq!(full.chain.status, AuditStepStatus::Valid);
    assert_eq!(full.metering.status, AuditStepStatus::Valid);
    assert_eq!(full.settlement.status, AuditStepStatus::Valid);
}

#[test]
fn verify_all_skips_metering_and_settlement_when_not_in_bundle() {
    let fx = make_key();
    let pack = make_pack(&fx);
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let full = auditor.verify_all(&AuditBundle {
        pack,
        metering: None,
        settlement: None,
        prior_after_hash: None,
    });
    assert_eq!(full.metering.status, AuditStepStatus::Skipped);
    assert_eq!(full.settlement.status, AuditStepStatus::Skipped);
    assert_eq!(full.status, AuditStepStatus::Valid);
}

#[test]
fn chain_walk_flags_link_mismatch() {
    let fx = make_key();
    let mut pack = make_multi_pack(&fx, 3);
    pack.records[1].before_hash = Some("deadbeef".to_string());
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let chain = auditor.verify_proof_chain(&pack.records, None);
    assert_eq!(chain.status, AuditStepStatus::Invalid);
    assert!(chain.steps.iter().any(|s| matches!(
        s.reason,
        Some(enfinitos_auditor::AuditReasonCode::ChainLinkMismatch)
    )));
}

#[test]
fn chain_walk_flags_empty_chain() {
    let auditor = Auditor::new(vec![]);
    let chain = auditor.verify_proof_chain(&[], None);
    assert_eq!(chain.status, AuditStepStatus::Invalid);
}

// ---------------------------------------------------------------------
// Cross-pack chain anchor (prior_after_hash).
//
// The platform seals packs in series: pack 2's records[0].beforeHash
// equals pack 1's LAST afterHash, not null (sealProofPack threads
// previousAfterHash — packages/sandbox-core/src/tenantState.ts).
// Passing the prior pack's tail hash verifies cross-pack continuity
// instead of falsely tripping GENESIS_BEFORE_HASH_NOT_NULL. Mirrors the
// TS verifyProofChain priorAfterHash semantics.
// ---------------------------------------------------------------------

#[test]
fn chain_walk_second_pack_fails_genesis_without_prior_after_hash() {
    let fx = make_key();
    let pack1 = make_multi_pack(&fx, 3);
    let tail = pack1.records.last().unwrap().after_hash.clone();
    let pack2 = make_chained_pack(&fx, 2, Some(tail), 3);
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    // Legacy behaviour retained: no anchor supplied → genesis violation.
    let report = auditor.verify_proof_chain(&pack2.records, None);
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert!(report.steps.iter().any(|s| matches!(
        s.reason,
        Some(enfinitos_auditor::AuditReasonCode::GenesisBeforeHashNotNull)
    )));
}

#[test]
fn chain_walk_second_pack_verifies_with_prior_after_hash() {
    let fx = make_key();
    let pack1 = make_multi_pack(&fx, 3);
    let tail = pack1.records.last().unwrap().after_hash.clone();
    let pack2 = make_chained_pack(&fx, 2, Some(tail.clone()), 3);
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let report = auditor.verify_proof_chain(&pack2.records, Some(&tail));
    assert_eq!(report.status, AuditStepStatus::Valid);
    assert!(report
        .steps
        .iter()
        .any(|s| s.target == "records[0].beforeHash"
            && s.status == AuditStepStatus::Valid));
}

#[test]
fn chain_walk_second_pack_flags_chain_link_mismatch_on_wrong_prior() {
    let fx = make_key();
    let pack1 = make_multi_pack(&fx, 3);
    let tail = pack1.records.last().unwrap().after_hash.clone();
    let pack2 = make_chained_pack(&fx, 2, Some(tail), 3);
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let wrong = "0".repeat(64);
    let report = auditor.verify_proof_chain(&pack2.records, Some(&wrong));
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert!(report.steps.iter().any(|s| s.target == "records[0].beforeHash"
        && matches!(
            s.reason,
            Some(enfinitos_auditor::AuditReasonCode::ChainLinkMismatch)
        )));
}

#[test]
fn verify_all_threads_prior_after_hash_for_second_pack() {
    let fx = make_key();
    let pack1 = make_multi_pack(&fx, 3);
    let tail = pack1.records.last().unwrap().after_hash.clone();
    let pack2 = make_chained_pack(&fx, 2, Some(tail.clone()), 3);
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);

    // Without the anchor: the chain walk flags a genesis violation.
    let without = auditor.verify_all(&AuditBundle {
        pack: pack2.clone(),
        metering: None,
        settlement: None,
        prior_after_hash: None,
    });
    assert_eq!(without.chain.status, AuditStepStatus::Invalid);

    // With the previous pack's tail afterHash: cross-pack continuity VALID.
    let with_prior = auditor.verify_all(&AuditBundle {
        pack: pack2,
        metering: None,
        settlement: None,
        prior_after_hash: Some(tail),
    });
    assert_eq!(with_prior.chain.status, AuditStepStatus::Valid);
    assert_eq!(with_prior.status, AuditStepStatus::Valid);
}

#[test]
fn metering_flags_unit_count_mismatch() {
    let fx = make_key();
    let pack = make_multi_pack(&fx, 2);
    let mut metering = make_metering(&pack);
    metering.records[0].unit_count = "9999.999999".to_string();
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let report = auditor.verify_metering_projection(
        &pack.records,
        &metering,
        Some(&pack.org_id),
    );
    assert_eq!(report.status, AuditStepStatus::Invalid);
}

#[test]
fn settlement_flags_amount_mismatch() {
    let fx = make_key();
    let pack = make_multi_pack(&fx, 2);
    let metering = make_metering(&pack);
    let mut settlement = make_settlement(&metering);
    settlement.lines[0].amount_cents += 1000;
    let auditor = Auditor::new(vec![fx.verification_key.clone()]);
    let report = auditor.verify_settlement_reconciliation(&metering, &settlement);
    assert_eq!(report.status, AuditStepStatus::Invalid);
}

// CRYPTO-04 — exact-cent multi-party split. Production splits a meter's gross
// across party shares as a deterministic integer split (floor per share +
// residual reabsorbed into the largest-share line). The auditor mirrors that
// split and requires EXACT-cent equality — no ±band — so a single-cent error
// on any line, including the residual-bearing largest line, is caught.

fn make_multi_party_split() -> (MeteringSummary, SettlementSummary) {
    let meter_idem = "meter_multiparty_x";
    let gross: i64 = 10001; // 0.7 / 0.25 / 0.05 -> 7000.7 / 2500.25 / 500.05

    let metering = MeteringSummary {
        schema_version: "metering.v1".to_string(),
        org_id: "org_test".to_string(),
        period_start: "2027-01-01T00:00:00.000Z".to_string(),
        period_end: "2027-02-01T00:00:00.000Z".to_string(),
        records: vec![MeterRecord {
            idem_key: meter_idem.to_string(),
            proof_receipt_id: "rcpt_multiparty_x".to_string(),
            unit_type: MeterUnitType::DwellSeconds,
            unit_count: "100.000000".to_string(),
            weight: "1.000000".to_string(),
            spatial_anchor_id: "anchor_x".to_string(),
            spatial_placement_id: None,
            observed_at: "2027-01-15T00:00:00.000Z".to_string(),
            status: MeterStatus::Projected,
        }],
        totals: None,
    };

    let lines = vec![
        // Largest share carries the +1 residual → 7001.
        SettlementLine {
            idem_key: settlement_idem_key(meter_idem, "TENANT", "SPATIAL_REVENUE_GROSS"),
            meter_record_idem_key: meter_idem.to_string(),
            party_role: SettlementPartyRole::Tenant,
            share: "0.700000".to_string(),
            ledger_account_code: "SPATIAL_REVENUE_GROSS".to_string(),
            amount_cents: 7001,
            currency: "GBP".to_string(),
            status: SettlementStatus::Projected,
        },
        SettlementLine {
            idem_key: settlement_idem_key(meter_idem, "VENUE", "SPATIAL_VENUE_PAYOUT"),
            meter_record_idem_key: meter_idem.to_string(),
            party_role: SettlementPartyRole::Venue,
            share: "0.250000".to_string(),
            ledger_account_code: "SPATIAL_VENUE_PAYOUT".to_string(),
            amount_cents: 2500,
            currency: "GBP".to_string(),
            status: SettlementStatus::Projected,
        },
        SettlementLine {
            idem_key: settlement_idem_key(meter_idem, "PLATFORM", "SPATIAL_PLATFORM_FEE"),
            meter_record_idem_key: meter_idem.to_string(),
            party_role: SettlementPartyRole::Platform,
            share: "0.050000".to_string(),
            ledger_account_code: "SPATIAL_PLATFORM_FEE".to_string(),
            amount_cents: 500,
            currency: "GBP".to_string(),
            status: SettlementStatus::Projected,
        },
    ];

    let mut meter_gross: BTreeMap<String, i64> = BTreeMap::new();
    meter_gross.insert(meter_idem.to_string(), gross);

    let settlement = SettlementSummary {
        schema_version: "settlement.v2".to_string(),
        org_id: "org_test".to_string(),
        period_start: "2027-01-01T00:00:00.000Z".to_string(),
        period_end: "2027-02-01T00:00:00.000Z".to_string(),
        currency: "GBP".to_string(),
        meter_gross,
        lines,
        totals: Some(SettlementTotals {
            gross_cents: 10001,
            net_to_tenant_cents: 7001,
            platform_fee_cents: 500,
        }),
    };

    (metering, settlement)
}

#[test]
fn settlement_exact_cent_multi_party_split_passes() {
    let (metering, settlement) = make_multi_party_split();
    let auditor = Auditor::new(vec![]);
    let report = auditor.verify_settlement_reconciliation(&metering, &settlement);
    assert_eq!(report.status, AuditStepStatus::Valid);
}

#[test]
fn settlement_exact_cent_flags_one_cent_error_on_residual_line() {
    let (metering, mut settlement) = make_multi_party_split();
    settlement.lines[0].amount_cents = 7000; // was 7001 — drop the residual cent
    let auditor = Auditor::new(vec![]);
    let report = auditor.verify_settlement_reconciliation(&metering, &settlement);
    assert_eq!(report.status, AuditStepStatus::Invalid);
}

#[test]
fn settlement_exact_cent_flags_one_cent_error_on_non_largest_line() {
    let (metering, mut settlement) = make_multi_party_split();
    settlement.lines[1].amount_cents = 2499; // was 2500
    let auditor = Auditor::new(vec![]);
    let report = auditor.verify_settlement_reconciliation(&metering, &settlement);
    assert_eq!(report.status, AuditStepStatus::Invalid);
}

// ── VER-02: legacy settlement.v1 idemKey (2-field) stays verifiable ───────
//
// Proof packs sealed before the CRYPTO-01 / settlement.v2 3-field idemKey used
// the 2-field `sha256(meterIdemKey|partyRole)`. The auditor must reconstruct
// per the summary's schemaVersion so old packs verify cleanly instead of every
// line flagging SETTLEMENT_IDEM_KEY_MISMATCH. Mirrors
// auditor-ts/__tests__/settlementAudit.test.ts (VER-02 block).

fn make_v1_single_line() -> (MeteringSummary, SettlementSummary) {
    let meter_idem = "meter_v1_legacy";
    let gross: i64 = 5000;
    let metering = MeteringSummary {
        schema_version: "metering.v1".to_string(),
        org_id: "org_v1".to_string(),
        period_start: "2026-01-01T00:00:00.000Z".to_string(),
        period_end: "2026-02-01T00:00:00.000Z".to_string(),
        records: vec![MeterRecord {
            idem_key: meter_idem.to_string(),
            proof_receipt_id: "rcpt_v1_legacy".to_string(),
            unit_type: MeterUnitType::DwellSeconds,
            unit_count: "50".to_string(),
            weight: "1".to_string(),
            spatial_anchor_id: "anchor_v1".to_string(),
            spatial_placement_id: None,
            observed_at: "2026-01-15T00:00:00.000Z".to_string(),
            status: MeterStatus::Accepted,
        }],
        totals: None,
    };
    let mut meter_gross: BTreeMap<String, i64> = BTreeMap::new();
    meter_gross.insert(meter_idem.to_string(), gross);
    let settlement = SettlementSummary {
        schema_version: "settlement.v1".to_string(),
        org_id: "org_v1".to_string(),
        period_start: "2026-01-01T00:00:00.000Z".to_string(),
        period_end: "2026-02-01T00:00:00.000Z".to_string(),
        currency: "GBP".to_string(),
        meter_gross,
        lines: vec![SettlementLine {
            // 2-field legacy key — no ledgerAccountCode in the hash domain.
            idem_key: settlement_idem_key_v1(meter_idem, "TENANT"),
            meter_record_idem_key: meter_idem.to_string(),
            party_role: SettlementPartyRole::Tenant,
            share: "1.000000".to_string(),
            ledger_account_code: "SPATIAL_REVENUE_GROSS".to_string(),
            amount_cents: gross,
            currency: "GBP".to_string(),
            status: SettlementStatus::Projected,
        }],
        totals: Some(SettlementTotals {
            gross_cents: gross,
            net_to_tenant_cents: gross,
            platform_fee_cents: 0,
        }),
    };
    (metering, settlement)
}

#[test]
fn settlement_v1_two_field_idem_key_verifies_valid() {
    let (metering, settlement) = make_v1_single_line();
    let auditor = Auditor::new(vec![]);
    let report = auditor.verify_settlement_reconciliation(&metering, &settlement);
    assert_eq!(report.status, AuditStepStatus::Valid);
    assert!(!report.steps.iter().any(|s| matches!(
        s.reason,
        Some(enfinitos_auditor::AuditReasonCode::SettlementIdemKeyMismatch)
    )));
}

#[test]
fn settlement_v1_wrong_idem_key_is_still_flagged() {
    let (metering, mut settlement) = make_v1_single_line();
    settlement.lines[0].idem_key = "0".repeat(64);
    let auditor = Auditor::new(vec![]);
    let report = auditor.verify_settlement_reconciliation(&metering, &settlement);
    assert!(report.steps.iter().any(|s| matches!(
        s.reason,
        Some(enfinitos_auditor::AuditReasonCode::SettlementIdemKeyMismatch)
    )));
}

#[test]
fn settlement_v2_using_old_two_field_key_is_flagged() {
    let (metering, mut settlement) = make_v1_single_line();
    settlement.schema_version = "settlement.v2".to_string(); // now 3-field is required
    let auditor = Auditor::new(vec![]);
    let report = auditor.verify_settlement_reconciliation(&metering, &settlement);
    assert!(report.steps.iter().any(|s| matches!(
        s.reason,
        Some(enfinitos_auditor::AuditReasonCode::SettlementIdemKeyMismatch)
    )));
}
