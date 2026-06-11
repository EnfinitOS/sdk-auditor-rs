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
use enfinitos_auditor::hashing::{meter_idem_key, settlement_idem_key, sha256_hex};
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
    let mut records: Vec<ProofRecord> = Vec::new();
    for i in 0..count {
        let issued_minute = i;
        let payload = ProofReceiptPayload {
            version: "1".to_string(),
            receipt_id: format!("rec_{:03}", i),
            correlation_id: None,
            spatial_anchor_id: format!("anchor_{}", i % 3),
            spatial_placement_id: None,
            issued_at: format!("2026-04-01T12:{:02}:00.000Z", issued_minute),
            rendered_at: format!("2026-04-01T11:59:{:02}.000Z", i),
            dwell_ms: 1000 + (i as i64) * 250,
            nonce: format!("nonce_{}", i),
            witness: None,
        };
        let before = if i == 0 {
            None
        } else {
            Some(records[i - 1].after_hash.clone())
        };
        records.push(sign_record(payload, fx, before));
    }
    SignedProofPack {
        envelope_version: "envelope.v1".to_string(),
        issued_at: "2026-04-01T13:00:00.000Z".to_string(),
        org_id: "org_test".to_string(),
        pack_id: "pack_multi".to_string(),
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
    let chain = auditor.verify_proof_chain(&pack.records);
    assert_eq!(chain.status, AuditStepStatus::Invalid);
    assert!(chain.steps.iter().any(|s| matches!(
        s.reason,
        Some(enfinitos_auditor::AuditReasonCode::ChainLinkMismatch)
    )));
}

#[test]
fn chain_walk_flags_empty_chain() {
    let auditor = Auditor::new(vec![]);
    let chain = auditor.verify_proof_chain(&[]);
    assert_eq!(chain.status, AuditStepStatus::Invalid);
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
