//! Canonical JSON encoder — byte-exact parity with the TS/Py ports.
//!
//! Two encoders, same dispatch rule as the other ports:
//!   1. `canonicalise_proof_payload`: field-ordered (proof receipts).
//!   2. `canonical_sort_keys`: recursive sort-key (rights/meter/etc.).

use crate::types::ProofReceiptPayload;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use std::collections::BTreeMap;

const PROOF_PAYLOAD_FIELDS: &[&str] = &[
    "version",
    "receiptId",
    "correlationId",
    "spatialAnchorId",
    "spatialPlacementId",
    "issuedAt",
    "renderedAt",
    "dwellMs",
    "nonce",
    "witness",
];

/// Field-ordered canonicalisation matching the platform's
/// `canonicalise.ts` byte-for-byte.
pub fn canonicalise_proof_payload(p: &ProofReceiptPayload) -> String {
    let mut out = String::with_capacity(256);
    out.push('{');
    for (i, field) in PROOF_PAYLOAD_FIELDS.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // JSON-encode the key.
        out.push('"');
        out.push_str(field);
        out.push_str("\":");

        let value_json = match *field {
            "version" => serde_json::to_string(&p.version).unwrap(),
            "receiptId" => serde_json::to_string(&p.receipt_id).unwrap(),
            "correlationId" => serde_json::to_string(&p.correlation_id).unwrap(),
            "spatialAnchorId" => serde_json::to_string(&p.spatial_anchor_id).unwrap(),
            "spatialPlacementId" => {
                serde_json::to_string(&p.spatial_placement_id).unwrap()
            }
            "issuedAt" => serde_json::to_string(&p.issued_at).unwrap(),
            "renderedAt" => serde_json::to_string(&p.rendered_at).unwrap(),
            "dwellMs" => serde_json::to_string(&p.dwell_ms).unwrap(),
            "nonce" => serde_json::to_string(&p.nonce).unwrap(),
            "witness" => serde_json::to_string(&p.witness).unwrap(),
            _ => unreachable!(),
        };
        out.push_str(&value_json);
    }
    out.push('}');
    out
}

/// Full signing input — `<canonical>|<keyId>`.
pub fn canonicalise_proof_signing_input(p: &ProofReceiptPayload, key_id: &str) -> String {
    format!("{}|{}", canonicalise_proof_payload(p), key_id)
}

/// Sort-key recursive encoder — used by the rights/meter chain.
pub fn canonical_sort_keys(value: &Value) -> String {
    let normalised = normalise(value);
    serde_json::to_string(&normalised).expect("infallible: normalised JSON")
}

fn normalise(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            // BTreeMap gives us lexicographic ordering at serialisation time.
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map.iter() {
                sorted.insert(k.clone(), normalise(v));
            }
            // serde_json::Value::Object preserves Map order on serialise via
            // a Map; we serialise from the BTreeMap directly to maintain
            // sort order regardless of feature flags.
            let mut out = serde_json::Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(normalise).collect())
        }
        other => other.clone(),
    }
}

/// Base64url-encode without padding.
pub fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64url-decode; accepts both padded and unpadded input.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Strip any padding the caller may have supplied.
    let trimmed = s.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed)
}

/// Strict base64url-decode (RFC 4648 §5) — exact parity with the TS
/// reference's `base64UrlDecode`. Rejects, with a stable message:
///   - whitespace anywhere in the input (malleability surface)
///   - explicit padding (`=`) — every EnfinitOS signer emits unpadded
///     base64url; accepting padded input would let the same logical
///     signature have two different wire spellings
///   - characters outside the base64url alphabet `[A-Za-z0-9_-]`
///   - lengths with `len % 4 == 1` (cannot represent a byte sequence)
///
/// Used by the provenance verifier; the permissive [`base64url_decode`]
/// above is kept for the pre-0.0.2 receipt path's behaviour.
pub fn base64url_decode_strict(s: &str) -> Result<Vec<u8>, String> {
    if s.chars().any(|c| c.is_whitespace()) {
        return Err("base64url_decode_strict: whitespace not allowed in base64url".into());
    }
    if s.contains('=') {
        return Err(
            "base64url_decode_strict: padding ('=') not allowed; use unpadded base64url".into(),
        );
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("base64url_decode_strict: invalid base64url character".into());
    }
    if s.len() % 4 == 1 {
        return Err("base64url_decode_strict: invalid length (mod 4 == 1)".into());
    }
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url_decode_strict: decode failed: {e}"))
}

/// sha256 of canonical input, returned as `sha256:<hex>`.
pub fn sha256_prefixed(canonical: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let bytes = hasher.finalize();
    format!("sha256:{}", hex_encode(bytes.as_slice()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(*b >> 4) as usize] as char);
        out.push(HEX[(*b & 0x0f) as usize] as char);
    }
    out
}
