//! Signed-export verification (export.v1) — round-trip + tamper tests.
//!
//! The fixture signs exactly the way the platform does
//! (packages/sandbox-core/src/exports.ts): canonical_sort_keys(payload),
//! sha256 hex of the canonical bytes, Ed25519 over `{canonical}|{keyId}`.
//! Mirrors packages/sdks/auditor-ts/__tests__/exports.test.ts.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use enfinitos_auditor::canonical_json::{base64url_encode, canonical_sort_keys};
use enfinitos_auditor::hashing::sha256_hex;
use enfinitos_auditor::keys::KeyDirectory;
use enfinitos_auditor::{
    verify_signed_export, AuditReasonCode, AuditStepKind, AuditStepStatus, SignedExport,
    VerificationKey,
};
use rand_core::OsRng;
use serde_json::{json, Value};

struct Fixture {
    signing_key: SigningKey,
    key_id: String,
    verification_key: VerificationKey,
}

fn make_key(key_id: &str) -> Fixture {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying: VerifyingKey = signing_key.verifying_key();
    let verification_key = VerificationKey {
        key_id: key_id.to_string(),
        algorithm: "ed25519".to_string(),
        public_key: base64url_encode(verifying.as_bytes()),
        not_before: "2020-01-01T00:00:00.000Z".to_string(),
        not_after: None,
        revoked_at: None,
        purpose: Some("test_fixture".to_string()),
    };
    Fixture {
        signing_key,
        key_id: key_id.to_string(),
        verification_key,
    }
}

fn directory_for(fx: &Fixture) -> KeyDirectory {
    KeyDirectory::from_local(vec![fx.verification_key.clone()])
        .expect("local key directory should be well-formed")
}

/// Mirror of the platform signer (sandbox-core exports.ts signExport).
fn sign_export(kind: &str, org_id: &str, payload: Value, fx: &Fixture) -> SignedExport {
    let payload_canonical = canonical_sort_keys(&payload);
    let payload_canonical_hash = sha256_hex(&payload_canonical);
    let signature = fx
        .signing_key
        .sign(format!("{}|{}", payload_canonical, fx.key_id).as_bytes());
    SignedExport {
        kind: kind.to_string(),
        envelope_version: "export.v1".to_string(),
        org_id: org_id.to_string(),
        exported_at: "2026-07-01T00:00:00.000Z".to_string(),
        key_id: fx.key_id.clone(),
        algorithm: "ed25519".to_string(),
        payload,
        payload_canonical,
        payload_canonical_hash,
        signature: base64url_encode(&signature.to_bytes()),
    }
}

fn metering_payload() -> Value {
    json!({
        "schemaVersion": "metering.v1",
        "orgId": "org_demo",
        "periodStart": "2026-06-01T00:00:00.000Z",
        "periodEnd": "2026-07-01T00:00:00.000Z",
        "records": [
            {
                "idemKey": "a".repeat(64),
                "proofReceiptId": "rcpt_demo_0001",
                "unitType": "ATTENTION_SECONDS",
                "unitCount": "6.500000",
                "weight": "1",
                "spatialAnchorId": "wsp_northgate",
                "spatialPlacementId": null,
                "observedAt": "2026-06-14T12:00:00.000Z",
                "status": "PROJECTED",
            }
        ],
        "totals": { "ATTENTION_SECONDS": "6.500000" },
    })
}

#[test]
fn round_trips_a_freshly_signed_metering_export_as_valid() {
    let fx = make_key("fixture_key_exports");
    let exp = sign_export("metering.export.v1", "org_demo", metering_payload(), &fx);
    let report = verify_signed_export(&exp, &directory_for(&fx));
    assert_eq!(report.status, AuditStepStatus::Valid);
    assert_eq!(report.kind, "metering.export.v1");
    assert!(report
        .steps
        .iter()
        .all(|s| s.status == AuditStepStatus::Valid));
}

#[test]
fn detects_a_tampered_payload_payload_canonical_mismatch() {
    let fx = make_key("fixture_key_exports");
    let mut exp = sign_export("metering.export.v1", "org_demo", metering_payload(), &fx);
    let mut tampered = metering_payload();
    tampered["orgId"] = json!("org_attacker");
    exp.payload = tampered;
    let report = verify_signed_export(&exp, &directory_for(&fx));
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert!(report.steps.iter().any(|s| matches!(
        s.reason,
        Some(AuditReasonCode::PayloadCanonicalMismatch)
    )));
}

#[test]
fn detects_a_tampered_transparency_hash() {
    let fx = make_key("fixture_key_exports");
    let mut exp = sign_export("metering.export.v1", "org_demo", metering_payload(), &fx);
    exp.payload_canonical_hash = "0".repeat(64);
    let report = verify_signed_export(&exp, &directory_for(&fx));
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert!(report.steps.iter().any(|s| matches!(
        s.reason,
        Some(AuditReasonCode::ExportPayloadHashMismatch)
    )));
}

#[test]
fn rejects_a_signature_from_a_different_key() {
    let fx = make_key("fixture_key_exports");
    let other = make_key("fixture_other");
    // Signed under `other`, presented as if signed by `fx` — the keyId is
    // bound into the signed bytes AND the key differs, so the signature
    // cannot verify.
    let mut exp = sign_export("settlement.export.v1", "org_demo", metering_payload(), &other);
    exp.key_id = fx.key_id.clone();
    let report = verify_signed_export(&exp, &directory_for(&fx));
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert!(report
        .steps
        .iter()
        .any(|s| matches!(s.reason, Some(AuditReasonCode::SignatureInvalid))));
}

#[test]
fn reports_an_unknown_key_id_as_a_key_lookup_failure() {
    let fx = make_key("fixture_key_exports");
    let stranger = make_key("fixture_stranger");
    let exp = sign_export("metering.export.v1", "org_demo", metering_payload(), &stranger);
    let report = verify_signed_export(&exp, &directory_for(&fx));
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert!(report.steps.iter().any(|s| s.kind == AuditStepKind::KeyLookup
        && matches!(s.reason, Some(AuditReasonCode::UnknownKeyId))));
}

#[test]
fn rejects_an_unsupported_envelope_version() {
    let fx = make_key("fixture_key_exports");
    let mut exp = sign_export("metering.export.v1", "org_demo", metering_payload(), &fx);
    exp.envelope_version = "export.v9".to_string();
    let report = verify_signed_export(&exp, &directory_for(&fx));
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert!(report.steps.iter().any(|s| matches!(
        s.reason,
        Some(AuditReasonCode::UnsupportedEnvelopeVersion)
    )));
}
