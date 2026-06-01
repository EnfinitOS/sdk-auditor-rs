//! Top-level Auditor facade — composes signature, chain, metering, and
//! settlement verification behind one method. Offline-first: keys must
//! be supplied at construction.

use crate::keys::KeyDirectory;
use crate::metering_audit::verify_metering_projection;
use crate::proof_chain::verify_proof_chain;
use crate::proof_pack::verify_proof_record;
use crate::settlement_audit::verify_settlement_reconciliation;
use crate::types::{
    AuditBundle, AuditReasonCode, AuditReport, AuditStep, AuditStepKind, AuditStepStatus,
    ChainAuditReport, FullAuditReport, KeysSnapshot, MeteringSummary,
    ProjectionAuditReport, ProofRecord, SettlementAuditReport, SettlementSummary,
    SignedProofPack, VerificationKey, SDK_VERSION,
};

#[derive(Debug)]
pub struct Auditor {
    key_directory: KeyDirectory,
}

impl Auditor {
    /// Construct from a pinned list of `VerificationKey`s (the
    /// regulator / offline-audit path).
    pub fn new(keys: Vec<VerificationKey>) -> Self {
        let key_directory = KeyDirectory::from_local(keys)
            .expect("local key directory should be well-formed");
        Self { key_directory }
    }

    /// Construct directly from an already-built key directory.
    pub fn with_directory(key_directory: KeyDirectory) -> Self {
        Self { key_directory }
    }

    /// Construct from a `/v1/runtime-keys` JSON envelope. Useful when
    /// the regulator received a pinned snapshot of the platform's
    /// directory.
    pub fn from_runtime_keys_json(json: &str) -> Result<Self, crate::errors::AuditorError> {
        Ok(Self {
            key_directory: KeyDirectory::from_runtime_keys_json(json)?,
        })
    }

    pub fn key_directory(&self) -> &KeyDirectory {
        &self.key_directory
    }

    // ----------------------------------------------------------------
    // Single primitives
    // ----------------------------------------------------------------

    /// Parse, verify signatures, and run envelope-level checks.
    pub fn verify_proof_pack(&self, pack: &SignedProofPack) -> AuditReport {
        let verified_at = chrono::Utc::now().to_rfc3339();
        let mut steps: Vec<AuditStep> = Vec::new();

        if pack.records.is_empty() {
            steps.push(AuditStep {
                target: "pack.records".to_string(),
                kind: AuditStepKind::Envelope,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::EmptyPack),
                message: "proof pack contains zero records — cannot audit".to_string(),
                detail: None,
            });
        } else {
            steps.push(AuditStep {
                target: "pack.records".to_string(),
                kind: AuditStepKind::Envelope,
                status: AuditStepStatus::Valid,
                reason: None,
                message: format!("pack contains {} record(s)", pack.records.len()),
                detail: None,
            });
        }

        if !crate::types::SUPPORTED_ENVELOPE_VERSIONS
            .iter()
            .any(|v| *v == pack.envelope_version.as_str())
        {
            steps.push(AuditStep {
                target: "pack.envelopeVersion".to_string(),
                kind: AuditStepKind::Envelope,
                status: AuditStepStatus::Invalid,
                reason: Some(AuditReasonCode::UnsupportedEnvelopeVersion),
                message: format!(
                    "envelopeVersion {:?} is not in {:?}",
                    pack.envelope_version,
                    crate::types::SUPPORTED_ENVELOPE_VERSIONS
                ),
                detail: None,
            });
        }

        for (i, rec) in pack.records.iter().enumerate() {
            steps.extend(verify_proof_record(rec, i, &self.key_directory));
        }

        let status = rollup_status(&steps);
        AuditReport {
            status,
            pack_id: pack.pack_id.clone(),
            org_id: pack.org_id.clone(),
            verified_at,
            sdk_version: SDK_VERSION.to_string(),
            envelope_version: pack.envelope_version.clone(),
            keys_snapshot: self.keys_snapshot(),
            steps,
        }
    }

    pub fn verify_proof_chain(&self, records: &[ProofRecord]) -> ChainAuditReport {
        verify_proof_chain(records)
    }

    pub fn verify_metering_projection(
        &self,
        records: &[ProofRecord],
        metering: &MeteringSummary,
        pack_org_id: Option<&str>,
    ) -> ProjectionAuditReport {
        verify_metering_projection(records, metering, pack_org_id)
    }

    pub fn verify_settlement_reconciliation(
        &self,
        metering: &MeteringSummary,
        settlement: &SettlementSummary,
    ) -> SettlementAuditReport {
        verify_settlement_reconciliation(metering, settlement)
    }

    /// One-shot full pipeline.
    pub fn verify_all(&self, bundle: &AuditBundle) -> FullAuditReport {
        let verified_at = chrono::Utc::now().to_rfc3339();
        let pack_report = self.verify_proof_pack(&bundle.pack);
        let chain_report = self.verify_proof_chain(&bundle.pack.records);

        let metering_ref = bundle
            .metering
            .as_ref()
            .or(bundle.pack.metering.as_ref());

        let metering_report = if let Some(m) = metering_ref {
            self.verify_metering_projection(
                &bundle.pack.records,
                m,
                Some(&bundle.pack.org_id),
            )
        } else {
            ProjectionAuditReport {
                status: AuditStepStatus::Skipped,
                verified_at: verified_at.clone(),
                sdk_version: SDK_VERSION.to_string(),
                proof_record_count: bundle.pack.records.len(),
                meter_record_count: 0,
                steps: vec![AuditStep {
                    target: "metering".to_string(),
                    kind: AuditStepKind::MeterProjection,
                    status: AuditStepStatus::Skipped,
                    reason: None,
                    message: "no metering summary in the bundle — skipped".to_string(),
                    detail: None,
                }],
            }
        };

        let settlement_ref = bundle
            .settlement
            .as_ref()
            .or(bundle.pack.settlement.as_ref());

        let settlement_report = match (metering_ref, settlement_ref) {
            (Some(m), Some(s)) => self.verify_settlement_reconciliation(m, s),
            _ => SettlementAuditReport {
                status: AuditStepStatus::Skipped,
                verified_at: verified_at.clone(),
                sdk_version: SDK_VERSION.to_string(),
                meter_record_count: metering_ref.map(|m| m.records.len()).unwrap_or(0),
                settlement_line_count: 0,
                steps: vec![AuditStep {
                    target: "settlement".to_string(),
                    kind: AuditStepKind::SettlementLine,
                    status: AuditStepStatus::Skipped,
                    reason: None,
                    message: "settlement reconciliation skipped — bundle lacks either metering or settlement summary".to_string(),
                    detail: None,
                }],
            },
        };

        let overall = rollup_overall(&[
            pack_report.status,
            chain_report.status,
            metering_report.status,
            settlement_report.status,
        ]);

        FullAuditReport {
            status: overall,
            pack_id: pack_report.pack_id.clone(),
            org_id: pack_report.org_id.clone(),
            verified_at,
            sdk_version: SDK_VERSION.to_string(),
            keys_snapshot: self.keys_snapshot(),
            pack: pack_report,
            chain: chain_report,
            metering: metering_report,
            settlement: settlement_report,
        }
    }

    fn keys_snapshot(&self) -> KeysSnapshot {
        let snap = self.key_directory.snapshot();
        KeysSnapshot {
            source: snap.source.clone(),
            snapshot_id: snap.snapshot_id.clone(),
            key_count: self.key_directory.size(),
            key_ids: self.key_directory.key_ids(),
        }
    }
}

fn rollup_status(steps: &[AuditStep]) -> AuditStepStatus {
    if steps.iter().any(|s| s.status == AuditStepStatus::Invalid) {
        AuditStepStatus::Invalid
    } else if steps.iter().all(|s| s.status == AuditStepStatus::Skipped) {
        AuditStepStatus::Skipped
    } else {
        AuditStepStatus::Valid
    }
}

fn rollup_overall(statuses: &[AuditStepStatus]) -> AuditStepStatus {
    if statuses.iter().any(|s| *s == AuditStepStatus::Invalid) {
        AuditStepStatus::Invalid
    } else if statuses.iter().all(|s| *s == AuditStepStatus::Skipped) {
        AuditStepStatus::Skipped
    } else if statuses.iter().all(|s| *s == AuditStepStatus::Valid) {
        AuditStepStatus::Valid
    } else {
        // Mix of Valid + Skipped — every step we actually ran passed;
        // SKIPPED is a conscious choice.
        AuditStepStatus::Valid
    }
}
