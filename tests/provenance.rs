//! Rights-provenance write-time signature verification tests.
//!
//! Mirrors `packages/sdks/auditor-ts/__tests__/provenance.test.ts`
//! case-for-case so the three SDKs stay behaviourally in sync:
//! honest chain VALID, field tamper → PROVENANCE_CANONICAL_MISMATCH,
//! signature splice → PROVENANCE_SIGNATURE_INVALID, malformed b64 →
//! PROVENANCE_SIGNATURE_MALFORMED, unknown key, key revocation,
//! mixed legacy back-compat, all-legacy SKIPPED, org splice, empty
//! set, pre-built directory acceptance.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use enfinitos_auditor::canonical_json::base64url_encode;
use enfinitos_auditor::provenance::{
    canonicalise_provenance_signing_input, verify_provenance_chain, verify_provenance_record,
    ProvenanceSigningFields, VerifyProvenanceChainOptions, PROVENANCE_SIGNING_VERSION,
};
use enfinitos_auditor::types::{
    AuditReasonCode, AuditStepKind, AuditStepStatus, ProvenanceRecord, VerificationKey,
};
use enfinitos_auditor::KeyDirectory;
use rand_core::OsRng;

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
    KeyDirectory::from_local(vec![fx.verification_key.clone()]).unwrap()
}

/// A representative RIGHT_ISSUED signing-fields shape — same values
/// as the TS suite's `issuedFields`.
fn issued_fields(org_id: &str) -> ProvenanceSigningFields {
    ProvenanceSigningFields {
        org_id: org_id.to_string(),
        event_type: "RIGHT_ISSUED".to_string(),
        right_id: Some("rgh_001".to_string()),
        basis_id: Some("bas_001".to_string()),
        offer_id: None,
        before_hash: None,
        after_hash: Some(format!("sha256:{}", "1".repeat(64))),
    }
}

/// Produce a write-time-signed rights-provenance record. Mirrors the
/// platform's provenanceSigner.ts `signProvenance` path byte-for-byte:
/// canonical pipe-delimited signing input, raw 64-byte Ed25519
/// signature, base64url unpadded.
fn sign_provenance_record(
    fields: &ProvenanceSigningFields,
    fx: &Fixture,
    occurred_at: &str,
) -> ProvenanceRecord {
    let payload_canonical = canonicalise_provenance_signing_input(fields, &fx.key_id);
    let signature = fx.signing_key.sign(payload_canonical.as_bytes());
    ProvenanceRecord {
        proof_id: format!("rp_{}", payload_canonical.len()),
        org_id: fields.org_id.clone(),
        provenance_event_type: fields.event_type.clone(),
        occurred_at: occurred_at.to_string(),
        right_id: fields.right_id.clone(),
        basis_id: fields.basis_id.clone(),
        offer_id: fields.offer_id.clone(),
        provenance_before_hash: fields.before_hash.clone(),
        provenance_after_hash: fields.after_hash.clone(),
        signature_algorithm: "ed25519".to_string(),
        signature: base64url_encode(&signature.to_bytes()),
        signer_key_id: fx.key_id.clone(),
        payload_canonical: Some(payload_canonical),
    }
}

/// A pre-Wave-14 record carrying only the platform's read-time
/// transport HMAC — not independently verifiable.
fn build_legacy_provenance_record(org_id: &str, event_type: &str) -> ProvenanceRecord {
    ProvenanceRecord {
        proof_id: "rp_legacy_001".to_string(),
        org_id: org_id.to_string(),
        provenance_event_type: event_type.to_string(),
        occurred_at: "2026-03-01T12:00:00.000Z".to_string(),
        right_id: Some("rgh_legacy".to_string()),
        basis_id: None,
        offer_id: None,
        provenance_before_hash: None,
        provenance_after_hash: Some(format!("sha256:{}", "a".repeat(64))),
        signature_algorithm: "hmac-sha256".to_string(),
        signature: format!("{}abcd", "c0ffee".repeat(10)),
        signer_key_id: format!("ledger.v1.{org_id}"),
        payload_canonical: None,
    }
}

const OCCURRED_AT: &str = "2026-05-29T12:00:00.000Z";

// ---------------------------------------------------------------------
// canonicalise_provenance_signing_input
// ---------------------------------------------------------------------

#[test]
fn canonical_input_produces_pipe_delimited_right_provenance_v1_form() {
    let out = canonicalise_provenance_signing_input(&issued_fields("org_test"), "key-1");
    assert_eq!(
        out,
        format!(
            "{}|org_test|RIGHT_ISSUED|rgh_001|bas_001|-|-|sha256:{}|key-1",
            PROVENANCE_SIGNING_VERSION,
            "1".repeat(64)
        )
    );
}

#[test]
fn canonical_input_encodes_none_and_empty_string_identically_as_dash() {
    let mut with_none = issued_fields("org_test");
    with_none.offer_id = None;
    let mut with_empty = issued_fields("org_test");
    with_empty.offer_id = Some(String::new());
    assert_eq!(
        canonicalise_provenance_signing_input(&with_none, "key-1"),
        canonicalise_provenance_signing_input(&with_empty, "key-1"),
    );
}

#[test]
fn canonical_input_includes_the_key_id() {
    let a = canonicalise_provenance_signing_input(&issued_fields("org_test"), "key-a");
    let b = canonicalise_provenance_signing_input(&issued_fields("org_test"), "key-b");
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------
// verify_provenance_record — write-time signed records
// ---------------------------------------------------------------------

#[test]
fn record_all_valid_steps_for_an_honest_record() {
    let fx = make_key("prov_key_1");
    let record = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);
    let steps = verify_provenance_record(&record, 0, &directory_for(&fx));
    assert!(!steps.is_empty());
    for s in &steps {
        assert_eq!(s.status, AuditStepStatus::Valid, "step failed: {:?}", s);
    }
}

#[test]
fn record_flags_canonical_mismatch_when_a_raw_field_is_edited_after_signing() {
    let fx = make_key("prov_key_tamper");
    let mut record = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);
    // Move the right to a different id without re-signing — the
    // classic post-write tamper the write-time signature exists for.
    record.right_id = Some("rgh_evil".to_string());
    let steps = verify_provenance_record(&record, 0, &directory_for(&fx));
    let fail = steps
        .iter()
        .find(|s| s.reason == Some(AuditReasonCode::ProvenanceCanonicalMismatch))
        .expect("expected PROVENANCE_CANONICAL_MISMATCH");
    assert_eq!(fail.status, AuditStepStatus::Invalid);
}

#[test]
fn record_flags_canonical_mismatch_when_payload_canonical_is_missing_on_ed25519() {
    let fx = make_key("prov_key_partial");
    let mut record = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);
    record.payload_canonical = None;
    let steps = verify_provenance_record(&record, 0, &directory_for(&fx));
    assert!(steps
        .iter()
        .any(|s| s.reason == Some(AuditReasonCode::ProvenanceCanonicalMismatch)));
}

#[test]
fn record_flags_signature_invalid_when_signature_bytes_are_spliced() {
    let fx = make_key("prov_key_splice");
    let record_a = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);
    let record_b = sign_provenance_record(
        &ProvenanceSigningFields {
            org_id: "org_test".to_string(),
            event_type: "RIGHT_SUSPENDED".to_string(),
            right_id: Some("rgh_001".to_string()),
            basis_id: Some("bas_001".to_string()),
            offer_id: None,
            before_hash: Some(format!("sha256:{}", "1".repeat(64))),
            after_hash: Some(format!("sha256:{}", "2".repeat(64))),
        },
        &fx,
        OCCURRED_AT,
    );
    // A's claims with B's signature — both internally well-formed.
    let mut spliced = record_a.clone();
    spliced.signature = record_b.signature.clone();
    let steps = verify_provenance_record(&spliced, 0, &directory_for(&fx));
    let fail = steps
        .iter()
        .find(|s| s.reason == Some(AuditReasonCode::ProvenanceSignatureInvalid))
        .expect("expected PROVENANCE_SIGNATURE_INVALID");
    assert_eq!(fail.status, AuditStepStatus::Invalid);
}

#[test]
fn record_flags_signature_malformed_for_bad_base64url_or_truncated_signature() {
    let fx = make_key("prov_key_malformed");
    let record = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);

    // Bad alphabet + padding — strict base64url rejects.
    let mut bad_alphabet = record.clone();
    bad_alphabet.signature = "not+base64url/safe==".to_string();
    let steps = verify_provenance_record(&bad_alphabet, 0, &directory_for(&fx));
    assert!(steps
        .iter()
        .any(|s| s.reason == Some(AuditReasonCode::ProvenanceSignatureMalformed)));

    // Truncated signature still canonical-matches (claims intact),
    // so the failure has to come from the byte-length gate.
    let mut truncated = record.clone();
    truncated.signature = record.signature[..16].to_string();
    let steps = verify_provenance_record(&truncated, 0, &directory_for(&fx));
    assert!(steps
        .iter()
        .any(|s| s.reason == Some(AuditReasonCode::ProvenanceSignatureMalformed)));
}

#[test]
fn record_flags_unknown_key_id_when_the_directory_lacks_the_signing_key() {
    let fx = make_key("prov_key_signing");
    let other = make_key("prov_key_other");
    let record = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);
    let steps = verify_provenance_record(&record, 0, &directory_for(&other));
    let fail = steps
        .iter()
        .find(|s| s.reason == Some(AuditReasonCode::UnknownKeyId))
        .expect("expected UNKNOWN_KEY_ID");
    assert_eq!(fail.kind, AuditStepKind::KeyLookup);
}

#[test]
fn record_flags_key_revoked_before_issuance_when_the_record_post_dates_revocation() {
    let fx = make_key("prov_key_revoked");
    let mut revoked_key = fx.verification_key.clone();
    revoked_key.revoked_at = Some("2026-01-01T00:00:00.000Z".to_string());
    let directory = KeyDirectory::from_local(vec![revoked_key]).unwrap();
    let record =
        sign_provenance_record(&issued_fields("org_test"), &fx, "2026-06-01T00:00:00.000Z");
    let steps = verify_provenance_record(&record, 0, &directory);
    assert!(steps
        .iter()
        .any(|s| s.reason == Some(AuditReasonCode::KeyRevokedBeforeIssuance)));
}

// ---------------------------------------------------------------------
// verify_provenance_record — legacy (pre-Wave-14) records
// ---------------------------------------------------------------------

#[test]
fn legacy_record_reports_an_informational_skipped_unsigned_record_never_invalid() {
    let fx = make_key("prov_key_legacy");
    let legacy = build_legacy_provenance_record("org_test", "RIGHT_ISSUED");
    let steps = verify_provenance_record(&legacy, 0, &directory_for(&fx));
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].status, AuditStepStatus::Skipped);
    assert_eq!(
        steps[0].reason,
        Some(AuditReasonCode::ProvenanceUnsignedRecord)
    );
    assert_eq!(steps[0].kind, AuditStepKind::ProvenanceSignature);
}

// ---------------------------------------------------------------------
// verify_provenance_chain
// ---------------------------------------------------------------------

#[test]
fn chain_valid_for_a_clean_signed_lifecycle() {
    let fx = make_key("prov_key_chain");
    let records = vec![
        sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT),
        sign_provenance_record(
            &ProvenanceSigningFields {
                org_id: "org_test".to_string(),
                event_type: "RIGHT_SUSPENDED".to_string(),
                right_id: Some("rgh_001".to_string()),
                basis_id: None,
                offer_id: None,
                before_hash: Some(format!("sha256:{}", "1".repeat(64))),
                after_hash: Some(format!("sha256:{}", "2".repeat(64))),
            },
            &fx,
            OCCURRED_AT,
        ),
        sign_provenance_record(
            &ProvenanceSigningFields {
                org_id: "org_test".to_string(),
                event_type: "RIGHT_REACTIVATED".to_string(),
                right_id: Some("rgh_001".to_string()),
                basis_id: None,
                offer_id: None,
                before_hash: Some(format!("sha256:{}", "2".repeat(64))),
                after_hash: Some(format!("sha256:{}", "3".repeat(64))),
            },
            &fx,
            OCCURRED_AT,
        ),
    ];

    let report = verify_provenance_chain(
        &records,
        &directory_for(&fx),
        &VerifyProvenanceChainOptions::default(),
    );
    assert_eq!(report.status, AuditStepStatus::Valid);
    assert_eq!(report.record_count, 3);
    assert_eq!(report.signed_record_count, 3);
    assert_eq!(report.unsigned_record_count, 0);
    assert!(report
        .steps
        .iter()
        .all(|s| s.status == AuditStepStatus::Valid));
}

#[test]
fn chain_invalid_and_points_at_the_tampered_records_index() {
    let fx = make_key("prov_key_chain_tamper");
    let mut records = vec![
        sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT),
        sign_provenance_record(
            &ProvenanceSigningFields {
                org_id: "org_test".to_string(),
                event_type: "RIGHT_REVOKED".to_string(),
                right_id: Some("rgh_001".to_string()),
                basis_id: None,
                offer_id: None,
                before_hash: Some(format!("sha256:{}", "1".repeat(64))),
                after_hash: Some(format!("sha256:{}", "9".repeat(64))),
            },
            &fx,
            OCCURRED_AT,
        ),
    ];
    // Flip the revocation into a reactivation without re-signing.
    records[1].provenance_event_type = "RIGHT_REACTIVATED".to_string();

    let report = verify_provenance_chain(
        &records,
        &directory_for(&fx),
        &VerifyProvenanceChainOptions::default(),
    );
    assert_eq!(report.status, AuditStepStatus::Invalid);
    let fail = report
        .steps
        .iter()
        .find(|s| {
            s.status == AuditStepStatus::Invalid
                && s.reason == Some(AuditReasonCode::ProvenanceCanonicalMismatch)
        })
        .expect("expected an INVALID PROVENANCE_CANONICAL_MISMATCH step");
    assert!(fail.target.contains("provenance[1]"));
}

#[test]
fn chain_mixed_signed_plus_legacy_sets_verify_valid_with_informational_findings() {
    let fx = make_key("prov_key_mixed");
    let records = vec![
        build_legacy_provenance_record("org_test", "RIGHT_ISSUED"),
        sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT),
    ];

    let report = verify_provenance_chain(
        &records,
        &directory_for(&fx),
        &VerifyProvenanceChainOptions::default(),
    );
    assert_eq!(report.status, AuditStepStatus::Valid);
    assert_eq!(report.signed_record_count, 1);
    assert_eq!(report.unsigned_record_count, 1);
    let informational: Vec<_> = report
        .steps
        .iter()
        .filter(|s| s.reason == Some(AuditReasonCode::ProvenanceUnsignedRecord))
        .collect();
    assert_eq!(informational.len(), 1);
    assert_eq!(informational[0].status, AuditStepStatus::Skipped);
}

#[test]
fn chain_all_legacy_set_reports_skipped() {
    let fx = make_key("prov_key_all_legacy");
    let records = vec![
        build_legacy_provenance_record("org_test", "RIGHT_ISSUED"),
        build_legacy_provenance_record("org_test", "RIGHT_SUSPENDED"),
    ];
    let report = verify_provenance_chain(
        &records,
        &directory_for(&fx),
        &VerifyProvenanceChainOptions::default(),
    );
    assert_eq!(report.status, AuditStepStatus::Skipped);
    assert_eq!(report.signed_record_count, 0);
    assert_eq!(report.unsigned_record_count, 2);
    assert!(report
        .steps
        .iter()
        .all(|s| s.status == AuditStepStatus::Skipped));
}

#[test]
fn chain_flags_org_mismatch_on_a_tenant_spliced_record_set() {
    let fx = make_key("prov_key_splice_org");
    let records = vec![
        sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT),
        sign_provenance_record(&issued_fields("org_other"), &fx, OCCURRED_AT),
    ];
    let report = verify_provenance_chain(
        &records,
        &directory_for(&fx),
        &VerifyProvenanceChainOptions {
            expected_org_id: Some("org_test".to_string()),
        },
    );
    assert_eq!(report.status, AuditStepStatus::Invalid);
    let fail = report
        .steps
        .iter()
        .find(|s| s.reason == Some(AuditReasonCode::ProvenanceOrgMismatch))
        .expect("expected PROVENANCE_ORG_MISMATCH");
    assert_eq!(fail.target, "provenance[1].orgId");
}

#[test]
fn chain_rejects_an_empty_record_set_as_invalid() {
    let fx = make_key("prov_key_empty");
    let report = verify_provenance_chain(
        &[],
        &directory_for(&fx),
        &VerifyProvenanceChainOptions::default(),
    );
    assert_eq!(report.status, AuditStepStatus::Invalid);
    assert_eq!(
        report.steps[0].reason,
        Some(AuditReasonCode::MalformedPack)
    );
}

#[test]
fn chain_accepts_a_pre_built_key_directory() {
    let fx = make_key("prov_key_dir");
    let record = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);
    let directory = directory_for(&fx);
    let report = verify_provenance_chain(
        std::slice::from_ref(&record),
        &directory,
        &VerifyProvenanceChainOptions::default(),
    );
    assert_eq!(report.status, AuditStepStatus::Valid);
}

#[test]
fn report_round_trips_through_serde_with_ts_wire_field_names() {
    // The report serialises with the same camelCase keys as the TS
    // report so a regulator can render the two side-by-side.
    let fx = make_key("prov_key_serde");
    let record = sign_provenance_record(&issued_fields("org_test"), &fx, OCCURRED_AT);
    let report = verify_provenance_chain(
        std::slice::from_ref(&record),
        &directory_for(&fx),
        &VerifyProvenanceChainOptions::default(),
    );
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"signedRecordCount\":1"));
    assert!(json.contains("\"unsignedRecordCount\":0"));
    assert!(json.contains("\"recordCount\":1"));
    assert!(json.contains("\"sdkVersion\":\"0.0.3\""));
    assert!(json.contains("\"provenance_signature\""));
}

#[test]
fn provenance_record_deserialises_from_the_platform_wire_shape() {
    // Wire JSON uses camelCase keys exactly as the platform's proof
    // read surface emits them (proof.v1).
    let wire = r#"{
        "proofId": "rp_wire_001",
        "orgId": "org_test",
        "provenanceEventType": "RIGHT_ISSUED",
        "occurredAt": "2026-05-29T12:00:00.000Z",
        "rightId": "rgh_001",
        "basisId": null,
        "offerId": null,
        "provenanceBeforeHash": null,
        "provenanceAfterHash": "sha256:aaaa",
        "signatureAlgorithm": "hmac-sha256",
        "signature": "deadbeef",
        "signerKeyId": "ledger.v1.org_test",
        "payloadCanonical": null
    }"#;
    let record: ProvenanceRecord = serde_json::from_str(wire).unwrap();
    assert_eq!(record.org_id, "org_test");
    assert_eq!(record.signature_algorithm, "hmac-sha256");
    assert!(record.payload_canonical.is_none());
}
