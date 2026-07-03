// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Group key types for asset groups (reissuable assets).

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};

use super::genesis::AssetId;
use super::types::*;
use crate::crypto::pedersen::tweaked_nums_key;
use crate::crypto::tapscript::{tap_branch_hash, tap_leaf_hash};

/// Version of the group key reveal that uses an OP_RETURN based
/// non-spendable leaf. Mirrors Go's `asset.OpReturnVersion`.
pub const OP_RETURN_VERSION: u8 = 1;

/// Version of the group key reveal that uses a Pedersen commitment
/// based non-spendable leaf. Mirrors Go's `asset.PedersenVersion`.
pub const PEDERSEN_VERSION: u8 = 2;

/// The BIP-341 base tapscript leaf version (0xc0).
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// A group key that links multiple asset issuances together.
///
/// Assets with the same group key are considered fungible with each other.
/// The group key is tweaked with the genesis asset ID to bind the key to a
/// specific asset lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKey {
    /// Construction version (V0 or V1).
    pub version: GroupKeyVersion,
    /// Raw (pre-tweak) public key.
    pub raw_key: SerializedKey,
    /// Tweaked group public key (33 bytes compressed).
    pub group_pub_key: SerializedKey,
    /// Root of the tapscript tree (0 or 32 bytes).
    pub tapscript_root: Vec<u8>,
    /// Witness stack authorizing group membership.
    pub witness: Vec<Vec<u8>>,
}

/// Revealed group key information for proof verification.
///
/// The reveal contains enough information to reconstruct the group public key
/// from the raw key and asset ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupKeyReveal {
    V0(GroupKeyRevealV0),
    V1(GroupKeyRevealV1),
}

impl GroupKeyReveal {
    /// Returns the raw (pre-tweak) key.
    pub fn raw_key(&self) -> &SerializedKey {
        match self {
            GroupKeyReveal::V0(v) => &v.raw_key,
            GroupKeyReveal::V1(v) => &v.internal_key,
        }
    }

    /// Returns the tapscript root bytes (0 or 32 bytes).
    pub fn tapscript_root(&self) -> &[u8] {
        match self {
            GroupKeyReveal::V0(v) => &v.tapscript_root,
            GroupKeyReveal::V1(v) => &v.tapscript.root,
        }
    }
}

/// V0 group key reveal: raw key + optional tapscript root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyRevealV0 {
    /// Raw key before tweaks.
    pub raw_key: SerializedKey,
    /// Tapscript root (0 or 32 bytes).
    pub tapscript_root: Vec<u8>,
}

/// V1 group key reveal: internal key + tapscript details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyRevealV1 {
    /// Non-spend leaf version.
    pub version: u8,
    /// Internal key before tweaks.
    pub internal_key: SerializedKey,
    /// Tapscript details.
    pub tapscript: GroupKeyRevealTapscript,
}

/// Tapscript details for V1 group key reveals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyRevealTapscript {
    /// Non-spend leaf version.
    pub version: u8,
    /// Final tapscript root hash.
    pub root: Vec<u8>,
    /// Optional custom subtree root.
    pub custom_subtree_root: Option<[u8; 32]>,
}

impl GroupKeyRevealTapscript {
    /// Checks that the group key reveal tapscript is well-formed and
    /// compliant: the final tapscript root hash must equal the root
    /// recomputed from the genesis asset ID and the custom subtree
    /// root. Mirrors Go's `GroupKeyRevealTapscript.Validate`
    /// (asset/group_key.go:580).
    pub fn validate(&self, asset_id: &AssetId) -> Result<(), AssetError> {
        let (tapscript, _) = new_group_key_tapscript_root(
            self.version,
            asset_id,
            self.custom_subtree_root,
        )?;

        if self.root != tapscript.root {
            return Err(AssetError::EncodingError(format!(
                "failed to derive tapscript root from internal key, \
                 genesis asset ID, and custom subtree root \
                 (expected_root={}, computed_root={})",
                crate::hex::encode(&self.root),
                crate::hex::encode(&tapscript.root),
            )));
        }

        Ok(())
    }
}

/// Pushes `data` onto `script` using btcd's canonical (minimal) push
/// rules, matching `txscript.ScriptBuilder.AddData`:
/// - empty data or a single zero byte pushes OP_0,
/// - a single byte in [1, 16] pushes OP_1..OP_16,
/// - a single 0x81 byte pushes OP_1NEGATE,
/// - otherwise the smallest direct/OP_PUSHDATA{1,2,4} encoding is used.
fn add_data_minimal_push(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0 => script.push(0x00), // OP_0
        1 if data[0] == 0x00 => script.push(0x00), // OP_0
        1 if (1..=16).contains(&data[0]) => {
            // OP_1 .. OP_16.
            script.push(0x50 + data[0]);
        }
        1 if data[0] == 0x81 => script.push(0x4f), // OP_1NEGATE
        n if n <= 75 => {
            script.push(n as u8);
            script.extend_from_slice(data);
        }
        n if n <= 0xff => {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(n as u8);
            script.extend_from_slice(data);
        }
        n if n <= 0xffff => {
            script.push(0x4d); // OP_PUSHDATA2
            script.extend_from_slice(&(n as u16).to_le_bytes());
            script.extend_from_slice(data);
        }
        n => {
            script.push(0x4e); // OP_PUSHDATA4
            script.extend_from_slice(&(n as u32).to_le_bytes());
            script.extend_from_slice(data);
        }
    }
}

/// Creates a new non-spendable tapscript leaf that includes the given
/// data, mirroring Go's `asset.NewNonSpendableScriptLeaf`
/// (asset/group_key.go:257). Returns the leaf version (always 0xc0)
/// and the script bytes.
///
/// - [`OP_RETURN_VERSION`]: `OP_RETURN [minimal push of data]`. Empty
///   data yields a bare `OP_RETURN` (Go passes nil data).
/// - [`PEDERSEN_VERSION`]: `PUSH32(<x-only tweaked NUMS key>)
///   OP_CHECKSIG`, where the key is the Pedersen commitment of the
///   data (zero padded to 32 bytes) turned into an xpub and derived at
///   path 0/0. Data longer than 32 bytes is rejected.
pub fn new_non_spendable_script_leaf(
    version: u8,
    data: &[u8],
) -> Result<(u8, Vec<u8>), AssetError> {
    let script = match version {
        // For the OP_RETURN based version, we use a single OP_RETURN
        // opcode followed by the data, if any.
        OP_RETURN_VERSION => {
            let mut script = vec![0x6a]; // OP_RETURN
            if !data.is_empty() {
                add_data_minimal_push(&mut script, data);
            }
            script
        }

        // For the Pedersen commitment based version, we use a single
        // OP_CHECKSIG with an un-spendable key.
        PEDERSEN_VERSION => {
            // Make sure we don't accidentally truncate the data.
            if data.len() > 32 {
                return Err(AssetError::EncodingError(
                    "data too large".into(),
                ));
            }

            let mut msg = [0u8; 32];
            msg[..data.len()].copy_from_slice(data);

            let (_, commit_point) =
                tweaked_nums_key(msg).map_err(|e| {
                    AssetError::EncodingError(format!(
                        "failed to derive tweaked NUMS key: {}",
                        e
                    ))
                })?;

            // schnorr.SerializePubKey: the 32-byte x coordinate.
            let commit_bytes = commit_point.serialize();
            let mut script = Vec::with_capacity(34);
            script.push(0x20); // OP_DATA_32
            script.extend_from_slice(&commit_bytes[1..33]);
            script.push(0xac); // OP_CHECKSIG
            script
        }

        other => {
            return Err(AssetError::EncodingError(format!(
                "unknown version {}",
                other
            )))
        }
    };

    Ok((TAPSCRIPT_LEAF_VERSION, script))
}

/// Computes the final tapscript root hash used to derive a V1 asset
/// group key, mirroring Go's `asset.NewGroupKeyTapscriptRoot`
/// (asset/group_key.go:519).
///
/// Without a custom subtree root the tree is a single leaf:
///
/// ```text
///       [tapscript_root]
///              |
/// [non_spend(<genesis asset ID>)]
/// ```
///
/// With a custom subtree root the tree has two layers:
///
/// ```text
///                        [tapscript_root]
///                          /          \
/// [non_spend(<genesis asset ID>)]   [tweaked_custom_branch]
///                                       /        \
///                               [non_spend()]   <custom_root_hash>
/// ```
///
/// Returns the reveal tapscript (which carries the final root) and the
/// 64-byte inclusion proof for the custom subtree: the empty
/// non-spendable leaf hash followed by the asset ID leaf hash. The
/// proof is returned regardless of whether a custom root is present,
/// matching Go.
pub fn new_group_key_tapscript_root(
    version: u8,
    genesis_asset_id: &AssetId,
    custom_root: Option<[u8; 32]>,
) -> Result<(GroupKeyRevealTapscript, [u8; 64]), AssetError> {
    // First, compute the hash of an empty (data-less) non-spendable
    // leaf. It is used as the sibling of the custom subtree root.
    let (empty_leaf_version, empty_leaf_script) =
        new_non_spendable_script_leaf(version, &[])?;
    let empty_leaf_hash =
        tap_leaf_hash(empty_leaf_version, &empty_leaf_script);

    // Construct a non-spendable tapscript leaf for the genesis asset
    // ID.
    let (id_leaf_version, id_leaf_script) =
        new_non_spendable_script_leaf(version, genesis_asset_id.as_bytes())?;
    let asset_id_leaf_hash =
        tap_leaf_hash(id_leaf_version, &id_leaf_script);

    // Without a custom root the tree is the single asset ID leaf; with
    // one, the right branch combines the empty leaf and the custom
    // root, and the final root branches that with the asset ID leaf.
    let root_hash = match custom_root {
        None => asset_id_leaf_hash,
        Some(custom_root) => {
            let right_hash =
                tap_branch_hash(&empty_leaf_hash, &custom_root);
            tap_branch_hash(&asset_id_leaf_hash, &right_hash)
        }
    };

    // Construct the custom subtree inclusion proof. This proof is
    // required to spend custom tapscript leaves in the tapscript tree.
    let mut inclusion_proof = [0u8; 64];
    inclusion_proof[..32].copy_from_slice(&empty_leaf_hash);
    inclusion_proof[32..].copy_from_slice(&asset_id_leaf_hash);

    Ok((
        GroupKeyRevealTapscript {
            version,
            root: root_hash.to_vec(),
            custom_subtree_root: custom_root,
        },
        inclusion_proof,
    ))
}

/// Derives a version 1 asset group key from an internal key and a
/// tapscript tree, mirroring Go's `asset.GroupPubKeyV1`
/// (asset/group_key.go:849). The tapscript tree is validated against
/// the genesis asset ID before the BIP-341 output key tweak is
/// applied. Returns the full (parity-carrying) compressed output key.
pub fn group_pub_key_v1(
    internal_key: &SerializedKey,
    tapscript_tree: &GroupKeyRevealTapscript,
    asset_id: &AssetId,
) -> Result<PublicKey, AssetError> {
    tapscript_tree.validate(asset_id).map_err(|e| {
        AssetError::EncodingError(format!(
            "group key reveal tapscript tree invalid: {}",
            e
        ))
    })?;

    let root: [u8; 32] = tapscript_tree.root.as_slice().try_into().map_err(
        |_| {
            AssetError::EncodingError(
                "group key reveal tapscript root invalid".into(),
            )
        },
    )?;

    full_taproot_output_key(internal_key, &root)
}

/// Computes the full (compressed, parity-carrying) taproot output key
/// for the given internal key and merkle root, matching Go's
/// `txscript.ComputeTaprootOutputKey` before schnorr serialization.
fn full_taproot_output_key(
    internal_key: &SerializedKey,
    merkle_root: &[u8; 32],
) -> Result<PublicKey, AssetError> {
    let x_only = XOnlyPublicKey::from_slice(internal_key.schnorr_bytes())
        .map_err(|e| {
            AssetError::InvalidKey(format!("invalid internal key: {}", e))
        })?;

    let (tweaked, parity) =
        crate::crypto::keys::tweak_pub_key(&x_only, Some(merkle_root))
            .map_err(|e| AssetError::InvalidKey(e.to_string()))?;

    Ok(PublicKey::from_x_only_public_key(tweaked, parity))
}

impl GroupKeyRevealV1 {
    /// Creates a new version 1 group key reveal from the non-spend
    /// leaf version, internal key, genesis asset ID and optional
    /// custom subtree root, mirroring Go's `NewGroupKeyRevealV1`
    /// (asset/group_key.go:668).
    pub fn new(
        version: u8,
        internal_key: SerializedKey,
        genesis_asset_id: &AssetId,
        custom_root: Option<[u8; 32]>,
    ) -> Result<Self, AssetError> {
        let (tapscript, _) = new_group_key_tapscript_root(
            version,
            genesis_asset_id,
            custom_root,
        )?;

        Ok(GroupKeyRevealV1 {
            version,
            internal_key,
            tapscript,
        })
    }

    /// Returns the group public key derived from the reveal, mirroring
    /// Go's `GroupKeyRevealV1.GroupPubKey` (asset/group_key.go:838).
    /// The reveal's tapscript tree is structurally validated against
    /// the asset ID as part of the derivation.
    pub fn group_pub_key(
        &self,
        asset_id: &AssetId,
    ) -> Result<PublicKey, AssetError> {
        group_pub_key_v1(&self.internal_key, &self.tapscript, asset_id)
    }

    /// Validates that this reveal is internally consistent for the
    /// given asset ID and that it derives the claimed group key: the
    /// tapscript root must be reproducible from the reveal's version,
    /// the asset ID and the custom subtree root, and the taproot tweak
    /// of the internal key with that root must equal the claimed key.
    pub fn validate(
        &self,
        asset_id: &AssetId,
        claimed_group_key: &SerializedKey,
    ) -> Result<(), AssetError> {
        let derived = self.group_pub_key(asset_id)?;

        if derived.serialize() != claimed_group_key.0 {
            return Err(AssetError::InvalidKey(
                "group key reveal doesn't match group key".into(),
            ));
        }

        Ok(())
    }
}

/// An external signing key, modeled after Go's `asset.ExternalKey`
/// (asset/asset.go:1170): an xpub derived at depth 3 of the BIP-86
/// hierarchy (e.g. m/86'/0'/0') plus the full 5-component derivation
/// path used to derive the actual key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalKey {
    /// The extended public key derived at depth 3 of the BIP-86
    /// hierarchy.
    pub xpub: Xpub,
    /// The full BIP-86 derivation path with exactly 5 components
    /// (e.g. m/86'/0'/0'/0/0); the last two components are derived
    /// from the xpub.
    pub derivation_path: Vec<u32>,
}

/// The BIP-32 hardened key offset.
const HARDENED_KEY_START: u32 = 0x8000_0000;

/// The BIP-86 purpose field (86').
const BIP86_PURPOSE: u32 = 86 + HARDENED_KEY_START;

impl ExternalKey {
    /// Ensures the external key meets the requirements for a BIP-86
    /// key structure, mirroring Go's `ExternalKey.Validate`.
    pub fn validate(&self) -> Result<(), AssetError> {
        if self.xpub.depth != 3 {
            return Err(AssetError::InvalidKey(
                "xpub must be derived at depth 3".into(),
            ));
        }

        if self.derivation_path.len() != 5 {
            return Err(AssetError::InvalidKey(
                "derivation path must have exactly 5 components".into(),
            ));
        }

        if self.derivation_path[0] != BIP86_PURPOSE {
            return Err(AssetError::InvalidKey(
                "xpub must be derived from BIP-0086 (Taproot) \
                 derivation path"
                    .into(),
            ));
        }

        Ok(())
    }

    /// Derives and returns the public key corresponding to the final
    /// index in the derivation path, mirroring Go's
    /// `ExternalKey.PubKey`: the fourth and fifth path components are
    /// derived (non-hardened) from the xpub.
    pub fn pub_key(&self) -> Result<PublicKey, AssetError> {
        self.validate()?;

        let secp = Secp256k1::new();
        let derive = |xpub: &Xpub, idx: u32| -> Result<Xpub, AssetError> {
            let child = ChildNumber::from_normal_idx(idx).map_err(|e| {
                AssetError::InvalidKey(format!(
                    "cannot derive hardened child from xpub: {}",
                    e
                ))
            })?;
            xpub.ckd_pub(&secp, child).map_err(|e| {
                AssetError::InvalidKey(format!("derivation failed: {}", e))
            })
        };

        let change_key = derive(&self.xpub, self.derivation_path[3])?;
        let index_key = derive(&change_key, self.derivation_path[4])?;

        Ok(index_key.public_key)
    }
}

/// Creates a new V1 group key from an external key and asset ID,
/// mirroring Go's `asset.NewGroupKeyV1FromExternal`
/// (asset/group_key.go:167). The optional custom root grafts a
/// user-defined tapscript subtree into the tree. Returns the group
/// public key and the final tapscript root.
pub fn new_group_key_v1_from_external(
    version: u8,
    external_key: &ExternalKey,
    asset_id: &AssetId,
    custom_root: Option<[u8; 32]>,
) -> Result<(PublicKey, [u8; 32]), AssetError> {
    let internal_key = external_key.pub_key().map_err(|e| {
        AssetError::InvalidKey(format!(
            "cannot derive group internal key from provided external \
             key (e.g. xpub): {}",
            e
        ))
    })?;

    let (tapscript, _) =
        new_group_key_tapscript_root(version, asset_id, custom_root)
            .map_err(|e| {
                AssetError::EncodingError(format!(
                    "cannot derive group key reveal tapscript root: {}",
                    e
                ))
            })?;

    let internal_serialized = SerializedKey(internal_key.serialize());
    let group_pub_key =
        group_pub_key_v1(&internal_serialized, &tapscript, asset_id)
            .map_err(|e| {
                AssetError::InvalidKey(format!(
                    "cannot derive group public key: {}",
                    e
                ))
            })?;

    let root: [u8; 32] =
        tapscript.root.as_slice().try_into().map_err(|_| {
            AssetError::EncodingError(
                "group key reveal tapscript root invalid".into(),
            )
        })?;

    Ok((group_pub_key, root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::{nums_xpub, taproot_nums_key};

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex_decode(s).try_into().unwrap()
    }

    /// The genesis asset ID 0x40, 0x41, ..., 0x5f used by the Go
    /// generated vectors below.
    fn test_asset_id() -> AssetId {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = 0x40 + i as u8;
        }
        AssetId(id)
    }

    /// The internal key used by the Go generated vectors: the public
    /// key of the private key 0x22 repeated 32 times
    /// (02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27).
    fn test_internal_key() -> SerializedKey {
        use bitcoin::secp256k1::SecretKey;
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        SerializedKey(PublicKey::from_secret_key(&secp, &sk).serialize())
    }

    const CUSTOM_ROOT: [u8; 32] = [0x77; 32];

    // Expected values below were generated by executing the Go
    // reference (asset/group_key.go, v0.8.99-alpha) with the same
    // inputs.

    #[test]
    fn test_non_spendable_leaf_op_return_go_vectors() {
        // Empty data: bare OP_RETURN.
        let (version, script) =
            new_non_spendable_script_leaf(OP_RETURN_VERSION, &[]).unwrap();
        assert_eq!(version, 0xc0);
        assert_eq!(script, vec![0x6a]);
        assert_eq!(
            tap_leaf_hash(version, &script),
            hex32(
                "46c7eccffefd2d573ec014130e508f0c9963ccebd7830409f7b1b1\
                 301725e9fa"
            )
        );

        // Asset ID data: OP_RETURN PUSH32 <id>.
        let asset_id = test_asset_id();
        let (version, script) = new_non_spendable_script_leaf(
            OP_RETURN_VERSION,
            asset_id.as_bytes(),
        )
        .unwrap();
        let mut expected = vec![0x6a, 0x20];
        expected.extend_from_slice(asset_id.as_bytes());
        assert_eq!(script, expected);
        assert_eq!(
            tap_leaf_hash(version, &script),
            hex32(
                "ad71cd94cb34d4524c0c1d820d506b02c5af0966de06d048eb3525\
                 c048c7efa4"
            )
        );
    }

    #[test]
    fn test_non_spendable_leaf_pedersen_go_vectors() {
        // Empty data commits to the all-zero message.
        let (version, script) =
            new_non_spendable_script_leaf(PEDERSEN_VERSION, &[]).unwrap();
        assert_eq!(version, 0xc0);
        assert_eq!(
            script,
            hex_decode(
                "2018e3b554e2fc16d265c00348b395aa6d04d7ce62ef2139d7ed3b\
                 c5b32e62bae3ac"
            )
        );
        assert_eq!(
            tap_leaf_hash(version, &script),
            hex32(
                "35dfd898c010c91641f4969b2e3a4b35832a55e3fc4ced371c9fa8\
                 3a9d0e2cf2"
            )
        );

        let asset_id = test_asset_id();
        let (version, script) = new_non_spendable_script_leaf(
            PEDERSEN_VERSION,
            asset_id.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            script,
            hex_decode(
                "20af033dabe7163ba40778f101538877aba082ed18cb9cb1f5345c\
                 17a4060074d5ac"
            )
        );
        assert_eq!(
            tap_leaf_hash(version, &script),
            hex32(
                "0df379065dfab08c9d5a216dd8460ff9cd6c48a42bc4362e08af90\
                 e10adb384c"
            )
        );
    }

    #[test]
    fn test_non_spendable_leaf_minimal_push_go_vectors() {
        // btcd's ScriptBuilder.AddData canonicalizes small values;
        // these scripts were generated by the Go reference.
        let cases: &[(&[u8], &str)] = &[
            (&[0x07], "6a57"), // OP_7
            (&[0x01], "6a51"), // OP_1
            (&[0x00], "6a00"), // OP_0
            (&[0x81], "6a4f"), // OP_1NEGATE
        ];
        for (data, expected) in cases {
            let (_, script) =
                new_non_spendable_script_leaf(OP_RETURN_VERSION, data)
                    .unwrap();
            assert_eq!(script, hex_decode(expected), "data {:02x?}", data);
        }

        // 75 bytes: largest direct push.
        let data75 = [0x07u8; 75];
        let (_, script) =
            new_non_spendable_script_leaf(OP_RETURN_VERSION, &data75)
                .unwrap();
        assert_eq!(script[..2], [0x6a, 0x4b]);
        assert_eq!(&script[2..], &data75[..]);

        // 76 bytes: OP_PUSHDATA1.
        let data76 = [0x07u8; 76];
        let (_, script) =
            new_non_spendable_script_leaf(OP_RETURN_VERSION, &data76)
                .unwrap();
        assert_eq!(script[..3], [0x6a, 0x4c, 0x4c]);
        assert_eq!(&script[3..], &data76[..]);
    }

    #[test]
    fn test_non_spendable_leaf_errors() {
        // Pedersen data longer than 32 bytes is rejected.
        let too_long = [0x01u8; 33];
        assert!(new_non_spendable_script_leaf(PEDERSEN_VERSION, &too_long)
            .is_err());

        // Unknown version is rejected.
        assert!(new_non_spendable_script_leaf(0, &[]).is_err());
        assert!(new_non_spendable_script_leaf(3, &[]).is_err());
    }

    #[test]
    fn test_group_key_tapscript_root_go_vectors() {
        let asset_id = test_asset_id();

        // OP_RETURN version, no custom root: root is the asset ID
        // leaf hash.
        let (ts, incl) = new_group_key_tapscript_root(
            OP_RETURN_VERSION,
            &asset_id,
            None,
        )
        .unwrap();
        assert_eq!(
            ts.root,
            hex_decode(
                "ad71cd94cb34d4524c0c1d820d506b02c5af0966de06d048eb3525\
                 c048c7efa4"
            )
        );
        assert_eq!(ts.version, OP_RETURN_VERSION);
        assert_eq!(ts.custom_subtree_root, None);
        assert_eq!(
            incl.to_vec(),
            hex_decode(
                "46c7eccffefd2d573ec014130e508f0c9963ccebd7830409f7b1b1\
                 301725e9faad71cd94cb34d4524c0c1d820d506b02c5af0966de06\
                 d048eb3525c048c7efa4"
            )
        );

        // OP_RETURN version, custom root.
        let (ts, incl) = new_group_key_tapscript_root(
            OP_RETURN_VERSION,
            &asset_id,
            Some(CUSTOM_ROOT),
        )
        .unwrap();
        assert_eq!(
            ts.root,
            hex_decode(
                "05dbfb3e42d6b1a64758ad8825e2ebf55265b434deefa14804b761\
                 7d0d3dc982"
            )
        );
        assert_eq!(ts.custom_subtree_root, Some(CUSTOM_ROOT));
        // The inclusion proof is identical whether or not a custom
        // root is present (Go).
        assert_eq!(
            incl.to_vec(),
            hex_decode(
                "46c7eccffefd2d573ec014130e508f0c9963ccebd7830409f7b1b1\
                 301725e9faad71cd94cb34d4524c0c1d820d506b02c5af0966de06\
                 d048eb3525c048c7efa4"
            )
        );

        // Pedersen version, no custom root.
        let (ts, incl) = new_group_key_tapscript_root(
            PEDERSEN_VERSION,
            &asset_id,
            None,
        )
        .unwrap();
        assert_eq!(
            ts.root,
            hex_decode(
                "0df379065dfab08c9d5a216dd8460ff9cd6c48a42bc4362e08af90\
                 e10adb384c"
            )
        );
        assert_eq!(
            incl.to_vec(),
            hex_decode(
                "35dfd898c010c91641f4969b2e3a4b35832a55e3fc4ced371c9fa8\
                 3a9d0e2cf20df379065dfab08c9d5a216dd8460ff9cd6c48a42bc4\
                 362e08af90e10adb384c"
            )
        );

        // Pedersen version, custom root.
        let (ts, _) = new_group_key_tapscript_root(
            PEDERSEN_VERSION,
            &asset_id,
            Some(CUSTOM_ROOT),
        )
        .unwrap();
        assert_eq!(
            ts.root,
            hex_decode(
                "3237fc79bf4787c1a47f6c49564b11928dc47c458f7748f66fe67c\
                 bd6fbd025b"
            )
        );
    }

    #[test]
    fn test_tapscript_validate() {
        let asset_id = test_asset_id();
        let (ts, _) = new_group_key_tapscript_root(
            PEDERSEN_VERSION,
            &asset_id,
            Some(CUSTOM_ROOT),
        )
        .unwrap();

        // Self-derived tapscript validates.
        ts.validate(&asset_id).unwrap();

        // Wrong asset ID is rejected.
        assert!(ts.validate(&AssetId([0x01; 32])).is_err());

        // Tampered root is rejected.
        let mut tampered = ts.clone();
        tampered.root[0] ^= 0x01;
        assert!(tampered.validate(&asset_id).is_err());

        // Tampered custom subtree root is rejected.
        let mut tampered = ts;
        tampered.custom_subtree_root = Some([0x78; 32]);
        assert!(tampered.validate(&asset_id).is_err());
    }

    #[test]
    fn test_group_pub_key_v1_go_vectors() {
        let asset_id = test_asset_id();
        let internal_key = test_internal_key();

        let cases: &[(u8, Option<[u8; 32]>, &str)] = &[
            (
                OP_RETURN_VERSION,
                None,
                "0230e4ba4f781f9e711578a510cf119f7ffc9f3b5e2e210a8763e6\
                 801b5314db12",
            ),
            (
                OP_RETURN_VERSION,
                Some(CUSTOM_ROOT),
                "03e990844fc8d57d31d5c82fde186a2e1f9b2c7f647104ce0fd6c4\
                 c528c27ecbd9",
            ),
            (
                PEDERSEN_VERSION,
                None,
                "033664c11e53983f64964223c2ed70c8ef288cfd34c7da60cbe19a\
                 23bb6166c9ed",
            ),
            (
                PEDERSEN_VERSION,
                Some(CUSTOM_ROOT),
                "030b76d83c1ab2b5665f60ddc5e36ca9f5ae1fed0df3c02566622c\
                 47673bc434c1",
            ),
        ];

        for (version, custom, expected) in cases {
            let (ts, _) = new_group_key_tapscript_root(
                *version, &asset_id, *custom,
            )
            .unwrap();
            let group_key =
                group_pub_key_v1(&internal_key, &ts, &asset_id).unwrap();
            assert_eq!(
                group_key.serialize().to_vec(),
                hex_decode(expected),
                "version {} custom {:?}",
                version,
                custom
            );
        }
    }

    #[test]
    fn test_group_key_reveal_v1_go_vectors_and_round_trip() {
        use crate::proof::decode::decode_group_key_reveal;
        use crate::proof::encode::encode_group_key_reveal;

        let asset_id = test_asset_id();
        let internal_key = test_internal_key();

        // Case 1: OP_RETURN version, no custom root.
        let reveal = GroupKeyRevealV1::new(
            OP_RETURN_VERSION,
            internal_key,
            &asset_id,
            None,
        )
        .unwrap();

        let encoded =
            encode_group_key_reveal(&GroupKeyReveal::V1(reveal.clone()));
        assert_eq!(
            encoded,
            hex_decode(
                "000101022102466d7fcae563e5cb09a0d1870bb5803448046178\
                 79a14949cf22285f1bae3f270420ad71cd94cb34d4524c0c1d82\
                 0d506b02c5af0966de06d048eb3525c048c7efa4"
            )
        );
        let decoded = decode_group_key_reveal(&encoded).unwrap();
        assert_eq!(decoded, GroupKeyReveal::V1(reveal.clone()));

        let group_key = reveal.group_pub_key(&asset_id).unwrap();
        assert_eq!(
            group_key.serialize().to_vec(),
            hex_decode(
                "0230e4ba4f781f9e711578a510cf119f7ffc9f3b5e2e210a8763e6\
                 801b5314db12"
            )
        );

        // Case 2: Pedersen version with custom root.
        let reveal = GroupKeyRevealV1::new(
            PEDERSEN_VERSION,
            internal_key,
            &asset_id,
            Some(CUSTOM_ROOT),
        )
        .unwrap();

        let encoded =
            encode_group_key_reveal(&GroupKeyReveal::V1(reveal.clone()));
        assert_eq!(
            encoded,
            hex_decode(
                "000102022102466d7fcae563e5cb09a0d1870bb5803448046178\
                 79a14949cf22285f1bae3f2704203237fc79bf4787c1a47f6c49\
                 564b11928dc47c458f7748f66fe67cbd6fbd025b072077777777\
                 777777777777777777777777777777777777777777777777777\
                 77777"
            )
        );
        let decoded = decode_group_key_reveal(&encoded).unwrap();
        assert_eq!(decoded, GroupKeyReveal::V1(reveal.clone()));

        let group_key = reveal.group_pub_key(&asset_id).unwrap();
        assert_eq!(
            group_key.serialize().to_vec(),
            hex_decode(
                "030b76d83c1ab2b5665f60ddc5e36ca9f5ae1fed0df3c02566622c\
                 47673bc434c1"
            )
        );
    }

    #[test]
    fn test_group_key_reveal_v1_validate() {
        let asset_id = test_asset_id();
        let internal_key = test_internal_key();

        let reveal = GroupKeyRevealV1::new(
            PEDERSEN_VERSION,
            internal_key,
            &asset_id,
            Some(CUSTOM_ROOT),
        )
        .unwrap();

        let group_key = reveal.group_pub_key(&asset_id).unwrap();
        let claimed = SerializedKey(group_key.serialize());

        // Self-derived reveal validates against the derived key.
        reveal.validate(&asset_id, &claimed).unwrap();

        // Wrong claimed group key is rejected.
        let mut wrong_claimed = claimed;
        wrong_claimed.0[1] ^= 0x01;
        assert!(reveal.validate(&asset_id, &wrong_claimed).is_err());

        // Tampered tapscript root is rejected.
        let mut tampered = reveal.clone();
        tampered.tapscript.root[0] ^= 0x01;
        assert!(tampered.validate(&asset_id, &claimed).is_err());

        // Tampered non-spend leaf version is rejected (root no longer
        // reproducible).
        let mut tampered = reveal.clone();
        tampered.version = OP_RETURN_VERSION;
        tampered.tapscript.version = OP_RETURN_VERSION;
        assert!(tampered.validate(&asset_id, &claimed).is_err());

        // Wrong asset ID is rejected.
        assert!(reveal.validate(&AssetId([0x01; 32]), &claimed).is_err());
    }

    /// Builds the test external key: the NUMS xpub (depth 3 by
    /// construction) with the BIP-86 path m/86'/0'/0'/0/0.
    fn test_external_key() -> ExternalKey {
        let (xpub, _) = nums_xpub(&taproot_nums_key().unwrap()).unwrap();
        const H: u32 = 0x8000_0000;
        ExternalKey {
            xpub,
            derivation_path: vec![86 + H, H, H, 0, 0],
        }
    }

    #[test]
    fn test_external_key_pub_key_go_vector() {
        let ek = test_external_key();
        ek.validate().unwrap();
        let pub_key = ek.pub_key().unwrap();
        assert_eq!(
            pub_key.serialize().to_vec(),
            hex_decode(
                "0218e3b554e2fc16d265c00348b395aa6d04d7ce62ef2139d7ed3b\
                 c5b32e62bae3"
            )
        );
    }

    #[test]
    fn test_external_key_validate_errors() {
        const H: u32 = 0x8000_0000;

        // Wrong path length.
        let mut ek = test_external_key();
        ek.derivation_path = vec![86 + H, H, H, 0];
        assert!(ek.pub_key().is_err());

        // Wrong purpose (not BIP-86).
        let mut ek = test_external_key();
        ek.derivation_path[0] = 84 + H;
        assert!(ek.pub_key().is_err());

        // Wrong depth.
        let mut ek = test_external_key();
        ek.xpub.depth = 2;
        assert!(ek.pub_key().is_err());

        // Hardened non-xpub-derivable component.
        let mut ek = test_external_key();
        ek.derivation_path[3] = H;
        assert!(ek.pub_key().is_err());
    }

    #[test]
    fn test_new_group_key_v1_from_external_go_vectors() {
        let asset_id = test_asset_id();
        let ek = test_external_key();

        let (group_key, root) = new_group_key_v1_from_external(
            PEDERSEN_VERSION,
            &ek,
            &asset_id,
            Some(CUSTOM_ROOT),
        )
        .unwrap();
        assert_eq!(
            group_key.serialize().to_vec(),
            hex_decode(
                "03a21501e30eed153b4a7cb144c18cfffbdcc078e56fab8acde3bc\
                 bfe3ac178955"
            )
        );
        assert_eq!(
            root,
            hex32(
                "3237fc79bf4787c1a47f6c49564b11928dc47c458f7748f66fe67c\
                 bd6fbd025b"
            )
        );

        let (group_key, root) = new_group_key_v1_from_external(
            OP_RETURN_VERSION,
            &ek,
            &asset_id,
            None,
        )
        .unwrap();
        assert_eq!(
            group_key.serialize().to_vec(),
            hex_decode(
                "035f76c1babdcbabcbc74b8241f8cd8ad24351406b0d6b9d0dd194\
                 43082c9f7e70"
            )
        );
        assert_eq!(
            root,
            hex32(
                "ad71cd94cb34d4524c0c1d820d506b02c5af0966de06d048eb3525\
                 c048c7efa4"
            )
        );
    }

    /// Ports the control-block check from Go's
    /// TestGroupKeyRevealEncodeDecode: reconstructing the tapscript
    /// root from a custom leaf script and the 64-byte inclusion proof
    /// (walking leaf -> empty-leaf sibling -> asset ID leaf sibling,
    /// as txscript.ControlBlock.RootHash does) must reproduce the
    /// reveal's tapscript root.
    #[test]
    fn test_custom_subtree_inclusion_proof_reconstructs_root() {
        let asset_id = test_asset_id();

        // Custom user script leaf (same bytes as the Go test).
        let custom_script = b"I'm a custom user script";
        let custom_leaf_hash = tap_leaf_hash(0xc0, custom_script);

        let (ts, inclusion_proof) = new_group_key_tapscript_root(
            PEDERSEN_VERSION,
            &asset_id,
            Some(custom_leaf_hash),
        )
        .unwrap();

        // Walk the merkle path like ControlBlock.RootHash: hash the
        // leaf with each inclusion proof node in order.
        let mut node = custom_leaf_hash;
        for sibling in inclusion_proof.chunks(32) {
            let sibling: [u8; 32] = sibling.try_into().unwrap();
            node = tap_branch_hash(&node, &sibling);
        }

        assert_eq!(node.to_vec(), ts.root);
    }

    #[test]
    fn test_derive_unique_script_key_go_vector() {
        use super::super::script_key::{
            derive_unique_script_key, ScriptKeyDerivationMethod,
        };

        let asset_id = test_asset_id();
        let internal_key = test_internal_key();

        let script_key = derive_unique_script_key(
            internal_key,
            &asset_id,
            ScriptKeyDerivationMethod::UniquePedersen,
        )
        .unwrap();

        // The script key is even-Y normalized (0x02 prefix), unlike
        // the full group key output (which retains parity 0x03 here).
        assert_eq!(
            script_key.pub_key.0.to_vec(),
            hex_decode(
                "023664c11e53983f64964223c2ed70c8ef288cfd34c7da60cbe19a\
                 23bb6166c9ed"
            )
        );

        let tweaked = script_key.tweaked.unwrap();
        assert_eq!(tweaked.raw_key, internal_key);
        assert_eq!(
            tweaked.tweak,
            hex_decode(
                "0df379065dfab08c9d5a216dd8460ff9cd6c48a42bc4362e08af90\
                 e10adb384c"
            )
        );
        assert_eq!(tweaked.key_type, ScriptKeyType::UniquePedersen);
    }
}
