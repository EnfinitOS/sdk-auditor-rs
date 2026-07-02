//! sha256 helpers — same three flavours as the TS/Py ports.

use sha2::{Digest, Sha256};

/// sha256 hex of a byte slice — the raw hex form (no `sha256:` prefix).
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let bytes = hasher.finalize();
    hex::encode(bytes.as_slice())
}

/// sha256 hex with the `"sha256:"` prefix the rights/basis/offer chain uses.
pub fn sha256_hex_prefixed(input: &str) -> String {
    format!("sha256:{}", sha256_hex(input))
}

/// MeterRecord idem key reconstruction.
pub fn meter_idem_key(proof_receipt_id: &str, unit_type: &str) -> String {
    sha256_hex(&format!("{proof_receipt_id}|{unit_type}"))
}

/// SettlementLine idem key reconstruction —
/// `sha256(meterRecordIdemKey|partyRole|ledgerAccountCode)` (settlement.v2,
/// CRYPTO-01). Content-hash binds the line to its ledger account code so two
/// lines for the same meter+role but different accounts can't collide.
pub fn settlement_idem_key(
    meter_record_idem_key: &str,
    party_role: &str,
    ledger_account_code: &str,
) -> String {
    sha256_hex(&format!(
        "{}|{}|{}",
        meter_record_idem_key, party_role, ledger_account_code
    ))
}

/// SettlementLine idem key reconstruction for legacy **settlement.v1** packs —
/// the 2-field `sha256(meterRecordIdemKey|partyRole)`. Kept so the auditor can
/// still verify proof packs sealed before the CRYPTO-01 / settlement.v2
/// 3-field key landed (VER-02). The caller selects v1 vs v2 by the summary's
/// `schemaVersion`; do not use this for v2 packs. Byte-identical to the TS
/// `settlementIdemKeyV1` and Python `settlement_idem_key_v1`.
pub fn settlement_idem_key_v1(meter_record_idem_key: &str, party_role: &str) -> String {
    sha256_hex(&format!("{}|{}", meter_record_idem_key, party_role))
}

/// Constant-time byte slice comparison.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time hex-string comparison.
pub fn constant_time_hex_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    constant_time_equal(a.as_bytes(), b.as_bytes())
}

// Tiny hex encoder so we don't pull in `hex` crate unnecessarily.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(*b >> 4) as usize] as char);
            out.push(HEX[(*b & 0x0f) as usize] as char);
        }
        out
    }
}
