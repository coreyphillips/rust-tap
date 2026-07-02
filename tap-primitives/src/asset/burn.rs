// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof-of-burn script keys.
//!
//! Mirrors Go's `asset/burn.go` (`DeriveBurnKey`) and the burn-key
//! detection helpers from `asset/witness.go` (`IsBurnKey`) and
//! `asset/asset.go` (`Asset.IsBurn`).

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};

use super::script_key::NUMS_BYTES;
use super::types::SerializedKey;
use super::witness::{PrevId, Witness};
use super::Asset;

/// Derives a provably un-spendable but unique key by tweaking the public
/// NUMS key with a tap tweak:
///
/// ```text
/// burnTweak = h_tapTweak(NUMSKey || outPoint || assetID || scriptKey)
/// burnKey = NUMSKey + burnTweak*G
/// ```
///
/// The `first_prev_id` must be the [`PrevId`] from the first input that is
/// being spent by the virtual transaction that contains the burn.
///
/// The tweak message is the Bitcoin wire encoding of the outpoint (txid
/// bytes as stored, u32 little-endian index) followed by the 32-byte asset
/// ID and the 32-byte schnorr-serialized (x-only) script key. Because that
/// message is longer than 32 bytes it can never be a valid tapscript merkle
/// root, which makes the script spend path provably invalid.
///
/// The result is normalized to even-Y parity (0x02 prefix), matching Go's
/// schnorr serialize + reparse round-trip: the burn key is only ever used
/// in its 32-byte x-only form on chain.
pub fn derive_burn_key(first_prev_id: &PrevId) -> SerializedKey {
    // Serialize the tweak message: wire outpoint || asset ID || x-only
    // script key.
    let mut msg = Vec::with_capacity(100);
    msg.extend_from_slice(&first_prev_id.out_point.txid);
    msg.extend_from_slice(&first_prev_id.out_point.vout.to_le_bytes());
    msg.extend_from_slice(first_prev_id.id.as_bytes());
    msg.extend_from_slice(first_prev_id.script_key.schnorr_bytes());

    // BIP-341 tap tweak over the NUMS internal key and the message:
    // t = tagged_hash("TapTweak", internal_x || msg).
    let nums = PublicKey::from_slice(&NUMS_BYTES)
        .expect("NUMS constant is a valid curve point");
    let (nums_x, _) = nums.x_only_public_key();

    let tag_hash = sha256::Hash::hash(b"TapTweak").to_byte_array();
    let mut engine = sha256::HashEngine::default();
    engine.input(&tag_hash);
    engine.input(&tag_hash);
    engine.input(&nums_x.serialize());
    engine.input(&msg);
    let tweak = sha256::Hash::from_engine(engine).to_byte_array();

    // burnKey = NUMS + t*G. The tweak is a hash output, so the chance of
    // it not being a valid scalar (or the result being infinity) is
    // negligible; Go's ComputeTaprootOutputKey panics in that case too.
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(tweak)
        .expect("tap tweak hash is a valid scalar");
    let (tweaked_x, _parity) = nums_x
        .add_tweak(&secp, &scalar)
        .expect("tap tweak result is a valid point");

    // Normalize to even-Y by serializing the x-only key with an 0x02
    // prefix, mirroring Go's schnorr.SerializePubKey + ParsePubKey.
    let mut out = [0u8; 33];
    out[0] = 0x02;
    out[1..].copy_from_slice(&tweaked_x.serialize());
    SerializedKey(out)
}

/// Returns true if the given script key is a valid burn key for the given
/// witness. Mirrors Go's `asset.IsBurnKey`.
///
/// If the witness is a split-commitment witness, the first `PrevId` is
/// taken from the split root asset's first witness; otherwise it is the
/// witness' own `prev_id`.
pub fn is_burn_key(script_key: &SerializedKey, witness: &Witness) -> bool {
    let prev_id = if let Some(ref split) = witness.split_commitment {
        // If this is a split output, then we need to look up the first
        // PrevId in the split root asset.
        let root_asset =
            match crate::encoding::asset::decode_asset(&split.root_asset) {
                Ok(asset) => asset,
                Err(_) => return false,
            };
        match root_asset
            .prev_witnesses
            .first()
            .and_then(|w| w.prev_id.clone())
        {
            Some(prev_id) => prev_id,
            None => return false,
        }
    } else {
        match witness.prev_id {
            Some(ref prev_id) => prev_id.clone(),
            None => return false,
        }
    };

    // Go compares full points via btcec.PublicKey.IsEqual, so the
    // parity byte matters: DeriveBurnKey is even-Y normalized, and an
    // odd-parity key with the same x coordinate is not a burn key.
    script_key.as_bytes() == derive_burn_key(&prev_id).as_bytes()
}

impl Asset {
    /// Returns true if this asset uses an un-spendable script key that was
    /// constructed using the proof-of-burn scheme. Mirrors Go's
    /// `Asset.IsBurn`.
    pub fn is_burn(&self) -> bool {
        // If there is no witness (yet?), then we can't tell if this is a
        // burn or not.
        if self.prev_witnesses.is_empty() {
            return false;
        }

        is_burn_key(self.script_key.serialized(), &self.prev_witnesses[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::{AssetId, OutPoint};

    fn test_prev_id() -> PrevId {
        PrevId {
            out_point: OutPoint {
                txid: [0x77; 32],
                vout: 123,
            },
            id: AssetId([0x01; 32]),
            script_key: SerializedKey([0x02; 33]),
        }
    }

    #[test]
    fn test_burn_key_deterministic() {
        let prev_id = test_prev_id();
        assert_eq!(derive_burn_key(&prev_id), derive_burn_key(&prev_id));
    }

    #[test]
    fn test_burn_key_unique_per_prev_id() {
        let prev_id_a = test_prev_id();
        let mut prev_id_b = test_prev_id();
        prev_id_b.out_point.vout = 124;

        assert_ne!(derive_burn_key(&prev_id_a), derive_burn_key(&prev_id_b));
    }

    #[test]
    fn test_burn_key_even_y() {
        let key = derive_burn_key(&test_prev_id());
        assert_eq!(key.0[0], 0x02);
    }

    #[test]
    fn test_is_burn_key_no_prev_id() {
        let witness = Witness {
            prev_id: None,
            tx_witness: vec![],
            split_commitment: None,
        };
        let key = derive_burn_key(&test_prev_id());
        assert!(!is_burn_key(&key, &witness));
    }
}
