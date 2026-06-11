//! Wire + domain types. Mirrors the TypeScript and Python ports
//! field-for-field. Serde-rename attributes keep the on-disk JSON keys
//! identical to the platform's canonical shape.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bumped on any semantic break in the SignedProofPack shape.
pub const SUPPORTED_ENVELOPE_VERSIONS: &[&str] = &["envelope.v1"];

/// Algorithm identifiers the SDK understands.
pub const SUPPORTED_SIGNATURE_ALGORITHMS: &[&str] = &["ed25519"];

/// SDK version stamped onto every audit report.
pub const SDK_VERSION: &str = "0.0.3";

pub type EnvelopeVersion = String;
pub type SignatureAlgorithm = String;

// ---------------------------------------------------------------------
// Verification keys
// ---------------------------------------------------------------------

/// One of N public keys the platform may have used to sign records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationKey {
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "notBefore")]
    pub not_before: String,
    #[serde(rename = "notAfter")]
    pub not_after: Option<String>,
    #[serde(rename = "revokedAt")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Wire envelope of `/v1/runtime-keys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeKeysResponse {
    pub ok: bool,
    #[serde(rename = "contractVersion")]
    pub contract_version: String,
    pub data: RuntimeKeysData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeKeysData {
    pub keys: Vec<VerificationKey>,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(default, rename = "snapshotId", skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

// ---------------------------------------------------------------------
// Proof pack
// ---------------------------------------------------------------------

/// Exactly the shape platform proof receipts emit, version "1".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofReceiptPayload {
    pub version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "correlationId")]
    pub correlation_id: Option<String>,
    #[serde(rename = "spatialAnchorId")]
    pub spatial_anchor_id: String,
    #[serde(rename = "spatialPlacementId")]
    pub spatial_placement_id: Option<String>,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "renderedAt")]
    pub rendered_at: String,
    #[serde(rename = "dwellMs")]
    pub dwell_ms: i64,
    pub nonce: String,
    pub witness: Option<String>,
}

/// A single signed receipt + provenance chain fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRecord {
    pub payload: ProofReceiptPayload,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub signature: String,
    #[serde(rename = "payloadCanonical")]
    pub payload_canonical: String,
    #[serde(rename = "beforeHash")]
    pub before_hash: Option<String>,
    #[serde(rename = "afterHash")]
    pub after_hash: String,
}

// ---------------------------------------------------------------------
// Rights-provenance records — Wave 14 write-time signing contract
// ---------------------------------------------------------------------

/// One rights-provenance ledger entry as the platform's proof read
/// surface emits it (apps/api/src/modules/proof/decoder.ts →
/// ProofRecord, proof.v1).
///
/// This is a DIFFERENT artefact from the spatial-chain [`ProofRecord`]
/// above: that one wraps a `ProofReceiptPayload` signed over a
/// canonical-JSON encoding; this one is a rights lifecycle event
/// (basis assert/verify/reject, right issue/suspend/resume/revoke/
/// expire, offer propose/accept/counter/reject/withdraw/expire,
/// challenge open/resolve/withdraw) signed over a flat pipe-delimited
/// canonical string:
///
/// ```text
/// rightProvenance.v1|<orgId>|<eventType>|<rightId|->|<basisId|->|
/// <offerId|->|<beforeHash|->|<afterHash|->|<keyId>
/// ```
///
/// where `-` encodes an absent field. The hand-rolled form is what
/// lets TS / Rust / Python verifiers reconstruct the signed bytes
/// without sharing a canonical-JSON library.
///
/// Signature presence is per-record:
///   - `signature_algorithm == "ed25519"` → write-time signed.
///     `signature` is the base64url (unpadded) 64-byte Ed25519
///     signature; `signer_key_id` matches a [`VerificationKey`];
///     `payload_canonical` carries the exact signed string as a
///     transparency aid.
///   - `signature_algorithm == "hmac-sha256"` → legacy (pre-Wave-14)
///     record. Read-time transport HMAC only; the verifier reports
///     `PROVENANCE_UNSIGNED_RECORD` as an informational SKIPPED step,
///     never INVALID — published 0.0.1-era exports keep verifying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// Stable record id (the RightProvenance row id).
    #[serde(rename = "proofId")]
    pub proof_id: String,
    /// Tenant the record belongs to. Part of the signing input.
    #[serde(rename = "orgId")]
    pub org_id: String,
    /// The platform's raw lifecycle event tag (e.g. RIGHT_ISSUED).
    /// Part of the signing input.
    #[serde(rename = "provenanceEventType")]
    pub provenance_event_type: String,
    /// ISO-8601 — when the event was recorded. Drives key-validity
    /// checks (plays the role of issuedAt).
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    /// Entity pointers — each part of the signing input; None when absent.
    #[serde(rename = "rightId")]
    pub right_id: Option<String>,
    #[serde(rename = "basisId")]
    pub basis_id: Option<String>,
    #[serde(rename = "offerId")]
    pub offer_id: Option<String>,
    /// Raw entity-chain hashes exactly as persisted (typically
    /// `sha256:<hex>`-prefixed; None on auxiliary birth rows).
    #[serde(rename = "provenanceBeforeHash")]
    pub provenance_before_hash: Option<String>,
    #[serde(rename = "provenanceAfterHash")]
    pub provenance_after_hash: Option<String>,
    /// "ed25519" (write-time signed) or "hmac-sha256" (legacy).
    #[serde(rename = "signatureAlgorithm")]
    pub signature_algorithm: String,
    /// For ed25519 records: base64url (unpadded) 64-byte Ed25519
    /// signature over the canonical signing input. For hmac-sha256
    /// records: the platform's transport HMAC (hex) — opaque here.
    pub signature: String,
    /// For ed25519 records: the signing key id, resolvable in the
    /// published verification-key directory. For hmac-sha256 records:
    /// the synthetic `ledger.v1.<orgId>` tag.
    #[serde(rename = "signerKeyId")]
    pub signer_key_id: String,
    /// For ed25519 records: the exact canonical string that was
    /// signed. None on legacy records.
    #[serde(rename = "payloadCanonical")]
    pub payload_canonical: Option<String>,
}

/// `verify_provenance_chain` output. Same shape family as
/// [`ChainAuditReport`], with the signed/unsigned partition surfaced
/// so a regulator can quote "N of M records carry write-time
/// signatures" directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceAuditReport {
    pub status: AuditStepStatus,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
    /// Records carrying a write-time Ed25519 signature.
    #[serde(rename = "signedRecordCount")]
    pub signed_record_count: usize,
    /// Legacy records (read-time HMAC only) — informational.
    #[serde(rename = "unsignedRecordCount")]
    pub unsigned_record_count: usize,
    pub steps: Vec<AuditStep>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MeterUnitType {
    #[serde(rename = "DWELL_SECONDS")]
    DwellSeconds,
    #[serde(rename = "IMPRESSION_IN_PLACE")]
    ImpressionInPlace,
    #[serde(rename = "ATTENTION_SECONDS")]
    AttentionSeconds,
    #[serde(rename = "OCCUPANCY_WEIGHTED_EXPOSURE")]
    OccupancyWeightedExposure,
    #[serde(rename = "COMPLIANT_DELIVERY_MINUTE")]
    CompliantDeliveryMinute,
    #[serde(rename = "CUSTOM")]
    Custom,
}

impl MeterUnitType {
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            MeterUnitType::DwellSeconds => "DWELL_SECONDS",
            MeterUnitType::ImpressionInPlace => "IMPRESSION_IN_PLACE",
            MeterUnitType::AttentionSeconds => "ATTENTION_SECONDS",
            MeterUnitType::OccupancyWeightedExposure => "OCCUPANCY_WEIGHTED_EXPOSURE",
            MeterUnitType::CompliantDeliveryMinute => "COMPLIANT_DELIVERY_MINUTE",
            MeterUnitType::Custom => "CUSTOM",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeterStatus {
    #[serde(rename = "PROJECTED")]
    Projected,
    #[serde(rename = "ACCEPTED")]
    Accepted,
    #[serde(rename = "SETTLED")]
    Settled,
    #[serde(rename = "VOID")]
    Void,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeterRecord {
    #[serde(rename = "idemKey")]
    pub idem_key: String,
    #[serde(rename = "proofReceiptId")]
    pub proof_receipt_id: String,
    #[serde(rename = "unitType")]
    pub unit_type: MeterUnitType,
    #[serde(rename = "unitCount")]
    pub unit_count: String,
    pub weight: String,
    #[serde(rename = "spatialAnchorId")]
    pub spatial_anchor_id: String,
    #[serde(rename = "spatialPlacementId")]
    pub spatial_placement_id: Option<String>,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    pub status: MeterStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeteringSummary {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
    #[serde(rename = "periodStart")]
    pub period_start: String,
    #[serde(rename = "periodEnd")]
    pub period_end: String,
    pub records: Vec<MeterRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SettlementPartyRole {
    #[serde(rename = "TENANT")]
    Tenant,
    #[serde(rename = "VENUE")]
    Venue,
    #[serde(rename = "CUSTOMER")]
    Customer,
    #[serde(rename = "PLATFORM")]
    Platform,
    // The enterprise settlement rebuild (May 2026) widened the
    // platform's role union — counterparty-addressed splits can pay
    // agencies, affiliates, resellers, and tax authorities. Without
    // these variants the strict serde enum REJECTS packs containing
    // such lines at deserialisation time, even though every
    // settlement check (idem-key reconstruction, share sums, amount
    // recomputation) is role-agnostic. Keep in field-for-field
    // parity with sandbox-core + auditor-ts.
    #[serde(rename = "AGENCY")]
    Agency,
    #[serde(rename = "AFFILIATE")]
    Affiliate,
    #[serde(rename = "RESELLER")]
    Reseller,
    #[serde(rename = "TAX_AUTHORITY")]
    TaxAuthority,
}

impl SettlementPartyRole {
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            SettlementPartyRole::Tenant => "TENANT",
            SettlementPartyRole::Venue => "VENUE",
            SettlementPartyRole::Customer => "CUSTOMER",
            SettlementPartyRole::Platform => "PLATFORM",
            SettlementPartyRole::Agency => "AGENCY",
            SettlementPartyRole::Affiliate => "AFFILIATE",
            SettlementPartyRole::Reseller => "RESELLER",
            SettlementPartyRole::TaxAuthority => "TAX_AUTHORITY",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SettlementStatus {
    #[serde(rename = "PROJECTED")]
    Projected,
    #[serde(rename = "ACCEPTED")]
    Accepted,
    #[serde(rename = "POSTED")]
    Posted,
    #[serde(rename = "VOID")]
    Void,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementLine {
    /// Content-hash idem key. settlement.v2 (CRYPTO-01):
    /// `sha256(meterRecordIdemKey|partyRole|ledgerAccountCode)`. The
    /// 0.0.2-era form hashed only `meterRecordIdemKey|partyRole`.
    #[serde(rename = "idemKey")]
    pub idem_key: String,
    #[serde(rename = "meterRecordIdemKey")]
    pub meter_record_idem_key: String,
    #[serde(rename = "partyRole")]
    pub party_role: SettlementPartyRole,
    pub share: String,
    /// Ledger account the split posts to (e.g. `SPATIAL_REVENUE_GROSS`).
    /// settlement.v2 folds this into the line idem key.
    #[serde(rename = "ledgerAccountCode")]
    pub ledger_account_code: String,
    #[serde(rename = "amountCents")]
    pub amount_cents: i64,
    pub currency: String,
    pub status: SettlementStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementTotals {
    #[serde(rename = "grossCents")]
    pub gross_cents: i64,
    #[serde(rename = "netToTenantCents")]
    pub net_to_tenant_cents: i64,
    #[serde(rename = "platformFeeCents")]
    pub platform_fee_cents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementSummary {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
    #[serde(rename = "periodStart")]
    pub period_start: String,
    #[serde(rename = "periodEnd")]
    pub period_end: String,
    pub currency: String,
    #[serde(rename = "meterGross")]
    pub meter_gross: BTreeMap<String, i64>,
    pub lines: Vec<SettlementLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<SettlementTotals>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedProofPack {
    #[serde(rename = "envelopeVersion")]
    pub envelope_version: EnvelopeVersion,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
    #[serde(rename = "packId")]
    pub pack_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub records: Vec<ProofRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering: Option<MeteringSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<SettlementSummary>,
}

#[derive(Debug, Clone)]
pub struct ProofPack {
    pub envelope_version: EnvelopeVersion,
    pub issued_at: String,
    pub org_id: String,
    pub pack_id: String,
    pub records: Vec<ProofRecord>,
}

#[derive(Debug, Clone)]
pub struct AuditBundle {
    pub pack: SignedProofPack,
    pub metering: Option<MeteringSummary>,
    pub settlement: Option<SettlementSummary>,
}

// ---------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditStepStatus {
    #[serde(rename = "VALID")]
    Valid,
    #[serde(rename = "INVALID")]
    Invalid,
    #[serde(rename = "SKIPPED")]
    Skipped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditStepKind {
    #[serde(rename = "envelope")]
    Envelope,
    #[serde(rename = "signature")]
    Signature,
    #[serde(rename = "canonicalisation")]
    Canonicalisation,
    #[serde(rename = "chain_link")]
    ChainLink,
    #[serde(rename = "meter_projection")]
    MeterProjection,
    #[serde(rename = "meter_total")]
    MeterTotal,
    #[serde(rename = "settlement_line")]
    SettlementLine,
    #[serde(rename = "settlement_total")]
    SettlementTotal,
    #[serde(rename = "key_lookup")]
    KeyLookup,
    // Wave 14 Phase 2 — rights-provenance write-time signature checks.
    #[serde(rename = "provenance_signature")]
    ProvenanceSignature,
}

/// Reason codes are deliberately enumerable + stable across SDK releases.
/// Regulators and auditors cite them in formal reports. Adding codes is
/// forward-compatible; renaming them is a breaking change.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditReasonCode {
    // Envelope / pack-level
    #[serde(rename = "UNSUPPORTED_ENVELOPE_VERSION")]
    UnsupportedEnvelopeVersion,
    #[serde(rename = "MALFORMED_PACK")]
    MalformedPack,
    #[serde(rename = "EMPTY_PACK")]
    EmptyPack,
    #[serde(rename = "PACK_ORG_MISMATCH")]
    PackOrgMismatch,
    #[serde(rename = "UNSUPPORTED_ALGORITHM")]
    UnsupportedAlgorithm,
    // Signature
    #[serde(rename = "SIGNATURE_INVALID")]
    SignatureInvalid,
    #[serde(rename = "SIGNATURE_MALFORMED")]
    SignatureMalformed,
    #[serde(rename = "UNKNOWN_KEY_ID")]
    UnknownKeyId,
    #[serde(rename = "KEY_OUTSIDE_VALIDITY_WINDOW")]
    KeyOutsideValidityWindow,
    #[serde(rename = "KEY_REVOKED_BEFORE_ISSUANCE")]
    KeyRevokedBeforeIssuance,
    // Canonicalisation
    #[serde(rename = "PAYLOAD_CANONICAL_MISMATCH")]
    PayloadCanonicalMismatch,
    #[serde(rename = "AFTER_HASH_MISMATCH")]
    AfterHashMismatch,
    // Chain
    #[serde(rename = "GENESIS_BEFORE_HASH_NOT_NULL")]
    GenesisBeforeHashNotNull,
    #[serde(rename = "CHAIN_LINK_MISMATCH")]
    ChainLinkMismatch,
    #[serde(rename = "CHAIN_OUT_OF_ORDER")]
    ChainOutOfOrder,
    // Metering
    #[serde(rename = "METER_RECORD_FOR_UNKNOWN_PROOF")]
    MeterRecordForUnknownProof,
    #[serde(rename = "METER_UNIT_COUNT_MISMATCH")]
    MeterUnitCountMismatch,
    #[serde(rename = "METER_IDEM_KEY_MISMATCH")]
    MeterIdemKeyMismatch,
    #[serde(rename = "METER_TOTAL_MISMATCH")]
    MeterTotalMismatch,
    #[serde(rename = "METER_ORG_MISMATCH")]
    MeterOrgMismatch,
    // Settlement
    #[serde(rename = "SETTLEMENT_LINE_FOR_UNKNOWN_METER")]
    SettlementLineForUnknownMeter,
    #[serde(rename = "SETTLEMENT_SHARE_SUM_NOT_ONE")]
    SettlementShareSumNotOne,
    #[serde(rename = "SETTLEMENT_AMOUNT_MISMATCH")]
    SettlementAmountMismatch,
    #[serde(rename = "SETTLEMENT_IDEM_KEY_MISMATCH")]
    SettlementIdemKeyMismatch,
    #[serde(rename = "SETTLEMENT_TOTAL_MISMATCH")]
    SettlementTotalMismatch,
    #[serde(rename = "SETTLEMENT_ORG_MISMATCH")]
    SettlementOrgMismatch,
    // Rights-provenance write-time signing (Wave 14 Phase 2). Additive —
    // packs/exports produced before the platform shipped write-time
    // provenance signing never trip these.
    #[serde(rename = "PROVENANCE_SIGNATURE_INVALID")]
    ProvenanceSignatureInvalid,
    #[serde(rename = "PROVENANCE_SIGNATURE_MALFORMED")]
    ProvenanceSignatureMalformed,
    #[serde(rename = "PROVENANCE_CANONICAL_MISMATCH")]
    ProvenanceCanonicalMismatch,
    #[serde(rename = "PROVENANCE_UNSIGNED_RECORD")]
    ProvenanceUnsignedRecord,
    #[serde(rename = "PROVENANCE_ORG_MISMATCH")]
    ProvenanceOrgMismatch,
    // Keys
    #[serde(rename = "KEYS_FETCH_FAILED")]
    KeysFetchFailed,
    #[serde(rename = "KEYS_RESPONSE_MALFORMED")]
    KeysResponseMalformed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStep {
    pub target: String,
    pub kind: AuditStepKind,
    pub status: AuditStepStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonCode>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysSnapshot {
    pub source: String,
    #[serde(rename = "snapshotId")]
    pub snapshot_id: Option<String>,
    #[serde(rename = "keyCount")]
    pub key_count: usize,
    #[serde(rename = "keyIds")]
    pub key_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub status: AuditStepStatus,
    #[serde(rename = "packId")]
    pub pack_id: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    #[serde(rename = "envelopeVersion")]
    pub envelope_version: String,
    #[serde(rename = "keysSnapshot")]
    pub keys_snapshot: KeysSnapshot,
    pub steps: Vec<AuditStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAuditReport {
    pub status: AuditStepStatus,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
    pub steps: Vec<AuditStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionAuditReport {
    pub status: AuditStepStatus,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    #[serde(rename = "proofRecordCount")]
    pub proof_record_count: usize,
    #[serde(rename = "meterRecordCount")]
    pub meter_record_count: usize,
    pub steps: Vec<AuditStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementAuditReport {
    pub status: AuditStepStatus,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    #[serde(rename = "meterRecordCount")]
    pub meter_record_count: usize,
    #[serde(rename = "settlementLineCount")]
    pub settlement_line_count: usize,
    pub steps: Vec<AuditStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullAuditReport {
    pub status: AuditStepStatus,
    #[serde(rename = "packId")]
    pub pack_id: String,
    #[serde(rename = "orgId")]
    pub org_id: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    #[serde(rename = "keysSnapshot")]
    pub keys_snapshot: KeysSnapshot,
    pub pack: AuditReport,
    pub chain: ChainAuditReport,
    pub metering: ProjectionAuditReport,
    pub settlement: SettlementAuditReport,
}
