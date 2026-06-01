//! Verification key directory. Offline-first: callers feed in keys
//! they've pinned themselves, or supply a snapshot loaded from JSON.

use crate::errors::AuditorError;
use crate::types::{
    RuntimeKeysResponse, VerificationKey, SUPPORTED_SIGNATURE_ALGORITHMS,
};
use chrono::DateTime;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLookupResult {
    Hit(VerificationKey),
    Miss(KeyMissReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMissReason {
    UnknownKeyId,
    OutsideValidityWindow,
    RevokedBeforeIssuance,
}

#[derive(Debug, Clone)]
pub struct KeyDirectorySnapshot {
    pub source: String,
    pub snapshot_id: Option<String>,
    pub issued_at: Option<String>,
    pub keys: Vec<VerificationKey>,
}

#[derive(Debug, Clone)]
pub struct KeyDirectory {
    snapshot: KeyDirectorySnapshot,
    index: HashMap<String, VerificationKey>,
}

impl KeyDirectory {
    /// Construct from a snapshot. Duplicates in `keys` are rejected.
    pub fn from_snapshot(snapshot: KeyDirectorySnapshot) -> Result<Self, AuditorError> {
        let mut index = HashMap::new();
        for key in snapshot.keys.iter() {
            if index.contains_key(&key.key_id) {
                return Err(AuditorError::keys_malformed(format!(
                    "duplicate keyId in key directory: {}",
                    key.key_id
                )));
            }
            for_key_validate(key)?;
            index.insert(key.key_id.clone(), key.clone());
        }
        Ok(Self { snapshot, index })
    }

    /// Convenience: load from a list of local keys (regulator path).
    pub fn from_local(keys: Vec<VerificationKey>) -> Result<Self, AuditorError> {
        let snapshot = KeyDirectorySnapshot {
            source: "local".to_string(),
            snapshot_id: None,
            issued_at: None,
            keys,
        };
        Self::from_snapshot(snapshot)
    }

    /// Convenience: parse a `/v1/runtime-keys`-shaped JSON envelope.
    pub fn from_runtime_keys_json(json: &str) -> Result<Self, AuditorError> {
        let parsed: RuntimeKeysResponse = serde_json::from_str(json).map_err(|e| {
            AuditorError::keys_malformed(format!("runtime_keys envelope malformed: {e}"))
        })?;
        if !parsed.ok {
            return Err(AuditorError::keys_malformed(
                "runtime_keys envelope has ok=false",
            ));
        }
        let snapshot = KeyDirectorySnapshot {
            source: "platform".to_string(),
            snapshot_id: parsed.data.snapshot_id,
            issued_at: Some(parsed.data.issued_at),
            keys: parsed.data.keys,
        };
        Self::from_snapshot(snapshot)
    }

    pub fn snapshot(&self) -> &KeyDirectorySnapshot {
        &self.snapshot
    }

    pub fn size(&self) -> usize {
        self.index.len()
    }

    pub fn key_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.index.keys().cloned().collect();
        v.sort();
        v
    }

    /// Look up a key by id at a particular issuance instant. Applies
    /// validity-window and revocation checks at the call site.
    pub fn lookup(&self, key_id: &str, issued_at_iso: &str) -> KeyLookupResult {
        let key = match self.index.get(key_id) {
            Some(k) => k.clone(),
            None => return KeyLookupResult::Miss(KeyMissReason::UnknownKeyId),
        };

        let issued_at_ms = match parse_iso(issued_at_iso) {
            Some(ms) => ms,
            None => return KeyLookupResult::Miss(KeyMissReason::OutsideValidityWindow),
        };
        if let Some(nb) = parse_iso(&key.not_before) {
            if issued_at_ms < nb {
                return KeyLookupResult::Miss(KeyMissReason::OutsideValidityWindow);
            }
        }
        if let Some(na_str) = key.not_after.as_ref() {
            if let Some(na) = parse_iso(na_str) {
                if issued_at_ms > na {
                    return KeyLookupResult::Miss(KeyMissReason::OutsideValidityWindow);
                }
            }
        }
        if let Some(rev_str) = key.revoked_at.as_ref() {
            if let Some(rev) = parse_iso(rev_str) {
                if issued_at_ms > rev {
                    return KeyLookupResult::Miss(KeyMissReason::RevokedBeforeIssuance);
                }
            }
        }
        KeyLookupResult::Hit(key)
    }
}

fn for_key_validate(k: &VerificationKey) -> Result<(), AuditorError> {
    if !SUPPORTED_SIGNATURE_ALGORITHMS
        .iter()
        .any(|a| *a == k.algorithm.as_str())
    {
        return Err(AuditorError::keys_malformed(format!(
            "key {} algorithm {:?} is not supported (only 'ed25519')",
            k.key_id, k.algorithm
        )));
    }
    Ok(())
}

fn parse_iso(iso: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(iso).ok().map(|d| d.timestamp_millis())
}
