// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Virtual transaction construction for Taproot Assets.
//!
//! TAP uses a synthetic 1-input, 1-output "virtual transaction" to produce
//! a BIP-341 sighash for signing asset state transitions. This module
//! implements the construction to match the Go reference (`tapscript/tx.go`).

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness as BtcWitness,
};

use crate::asset::Asset;
use crate::encoding::asset::asset_to_leaf;
use crate::mssmt::{DefaultStore, FullTree, NodeHash};
use crate::vm::InputSet;

/// Errors from virtual transaction construction.
#[derive(Debug, Clone)]
pub enum VirtualTxError {
    /// An input witness references a PrevId not found in the input set.
    MissingInput(String),
    /// The witnesses consumed a different set of inputs than the
    /// provided previous assets (duplicate or omitted inputs).
    InputMismatch,
    /// The tree operation failed.
    TreeError(String),
    /// The sighash computation failed.
    SighashError(String),
    /// Invalid key data.
    InvalidKey(String),
}

impl std::fmt::Display for VirtualTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VirtualTxError::MissingInput(msg) => write!(f, "missing input: {}", msg),
            VirtualTxError::InputMismatch => write!(
                f,
                "the set of consumed inputs does not match the previous assets"
            ),
            VirtualTxError::TreeError(msg) => write!(f, "tree error: {}", msg),
            VirtualTxError::SighashError(msg) => write!(f, "sighash error: {}", msg),
            VirtualTxError::InvalidKey(msg) => write!(f, "invalid key: {}", msg),
        }
    }
}

impl std::error::Error for VirtualTxError {}

/// Computes the virtual prevout from an MS-SMT root.
///
/// `SHA256(root_hash || BE(root_sum))` becomes the txid, vout is always 0.
/// Matches Go's `VirtualTxInPrevOut` in `asset/tx.go`.
pub fn virtual_tx_in_prevout(root_hash: &NodeHash, root_sum: u64) -> OutPoint {
    let mut engine = sha256::HashEngine::default();
    engine.input(root_hash.as_bytes());
    engine.input(&root_sum.to_be_bytes());
    let hash = sha256::Hash::from_engine(engine);
    let txid = Txid::from_byte_array(hash.to_byte_array());
    OutPoint { txid, vout: 0 }
}

/// Builds the virtual transaction input by constructing an MS-SMT from
/// the previous assets.
///
/// Returns the `TxIn` and the (root_hash, root_sum) of the input tree.
/// Matches Go's `virtualTxIn` in `tapscript/tx.go`.
pub fn virtual_tx_in(
    new_asset: &Asset,
    prev_assets: &InputSet,
) -> Result<(TxIn, NodeHash, u64), VirtualTxError> {
    let mut tree = FullTree::new(DefaultStore::new());
    let mut inputs_consumed =
        std::collections::HashSet::with_capacity(prev_assets.len());

    for witness in &new_asset.prev_witnesses {
        let prev_id = witness
            .prev_id
            .as_ref()
            .ok_or_else(|| VirtualTxError::MissingInput("witness has no prev_id".into()))?;

        let prev_asset = prev_assets
            .get(prev_id)
            .ok_or_else(|| VirtualTxError::MissingInput("prev_id not in input set".to_string()))?;

        // Key = PrevId.Hash() = SHA256(outpoint || asset_id || schnorr_key)
        let key = prev_id.hash();
        // Leaf = TLV-encoded asset with amount as sum.
        let leaf = asset_to_leaf(prev_asset);

        tree.insert(key, leaf)
            .map_err(|e| VirtualTxError::TreeError(e.to_string()))?;

        inputs_consumed.insert(prev_id.clone());
    }

    // The set of referenced inputs must match the set of previous
    // assets, guarding against duplicate or omitted inputs. Mirrors
    // Go's ErrInputMismatch check in tapscript/tx.go.
    if inputs_consumed.len() != prev_assets.len() {
        return Err(VirtualTxError::InputMismatch);
    }

    let root = tree.root().map_err(|e| VirtualTxError::TreeError(e.to_string()))?;
    let root_hash = root.node_hash();
    let root_sum = root.node_sum();
    let prevout = virtual_tx_in_prevout(&root_hash, root_sum);

    let txin = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: BtcWitness::new(),
    };

    Ok((txin, root_hash, root_sum))
}

/// Builds the virtual transaction input for a grouped asset genesis.
///
/// The input tree commits to only the (witnessless) genesis asset,
/// inserted at the zero PrevId's hash. Matches Go's
/// `asset.VirtualGenesisTxIn`.
pub fn virtual_genesis_tx_in(
    new_asset: &Asset,
) -> Result<(TxIn, NodeHash, u64), VirtualTxError> {
    use crate::asset::PrevId;

    // Strip any group witness if present.
    let mut copy_no_witness = new_asset.clone();
    if copy_no_witness.has_genesis_witness_for_group() {
        copy_no_witness.prev_witnesses[0].tx_witness = vec![];
    }

    // Genesis grouped assets always use the zero PrevId as the MS-SMT
    // key since the asset has no real PrevId.
    let key = PrevId::ZERO.hash();
    let leaf = asset_to_leaf(&copy_no_witness);

    let mut tree = FullTree::new(DefaultStore::new());
    tree.insert(key, leaf)
        .map_err(|e| VirtualTxError::TreeError(e.to_string()))?;

    let root = tree.root().map_err(|e| VirtualTxError::TreeError(e.to_string()))?;
    let root_hash = root.node_hash();
    let root_sum = root.node_sum();
    let prevout = virtual_tx_in_prevout(&root_hash, root_sum);

    let txin = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ZERO,
        witness: BtcWitness::new(),
    };

    Ok((txin, root_hash, root_sum))
}

/// Computes the taproot script (`OP_1 <32-byte key>`) for a virtual output.
fn compute_taproot_script(key_bytes: &[u8; 32]) -> ScriptBuf {
    use bitcoin::opcodes::all::OP_PUSHBYTES_32;
    use bitcoin::opcodes::OP_TRUE;

    let mut script = Vec::with_capacity(34);
    script.push(OP_TRUE.to_u8()); // OP_1 (witness v1)
    script.push(OP_PUSHBYTES_32.to_u8());
    script.extend_from_slice(key_bytes);
    ScriptBuf::from_bytes(script)
}

/// Builds the virtual transaction output.
///
/// If the asset has a `split_commitment_root`, the output uses the root hash
/// as the taproot key and the root sum as the value.
///
/// Otherwise, builds a single-asset output MS-SMT with the witnessless asset
/// as a leaf, keyed by `SHA256(group_key || asset_id || schnorr_script_key)`.
///
/// Matches Go's `virtualTxOut` in `tapscript/tx.go`.
pub fn virtual_tx_out(tx_asset: &Asset) -> Result<TxOut, VirtualTxError> {
    // Case 1: Split commitment present — use the root directly.
    if let Some((ref root_hash, root_sum)) = tx_asset.split_commitment_root {
        let script = compute_taproot_script(root_hash.as_bytes());
        return Ok(TxOut {
            value: Amount::from_sat(root_sum),
            script_pubkey: script,
        });
    }

    // Case 2: Single asset — build output MS-SMT.
    // Key = SHA256(group_key || asset_id || schnorr_script_key)
    let group_key_bytes: [u8; 32] = if let Some(ref gk) = tx_asset.group_key {
        *gk.group_pub_key.schnorr_bytes()
    } else {
        [0u8; 32]
    };

    let asset_id = tx_asset.genesis.id();
    let script_key_schnorr = tx_asset.script_key.serialized().schnorr_bytes();

    let mut engine = sha256::HashEngine::default();
    engine.input(&group_key_bytes);
    engine.input(asset_id.as_bytes());
    engine.input(script_key_schnorr);
    let key = sha256::Hash::from_engine(engine).to_byte_array();

    // Create a copy of the asset without witnesses for the leaf.
    let mut copy = tx_asset.clone();
    for w in &mut copy.prev_witnesses {
        w.tx_witness = vec![];
    }

    let leaf = asset_to_leaf(&copy);

    let mut tree = FullTree::new(DefaultStore::new());
    tree.insert(key, leaf)
        .map_err(|e| VirtualTxError::TreeError(e.to_string()))?;

    let root = tree.root().map_err(|e| VirtualTxError::TreeError(e.to_string()))?;
    let root_hash = root.node_hash();
    let script = compute_taproot_script(root_hash.as_bytes());

    Ok(TxOut {
        value: Amount::from_sat(tx_asset.amount),
        script_pubkey: script,
    })
}

/// Constructs the virtual transaction (version 2, 1 input, 1 output).
///
/// Returns the transaction and the input tree's (root_hash, root_sum).
/// Matches Go's `VirtualTx` in `tapscript/tx.go`.
pub fn virtual_tx(
    new_asset: &Asset,
    prev_assets: &InputSet,
) -> Result<(Transaction, NodeHash, u64), VirtualTxError> {
    // Grouped asset geneses commit to only the genesis asset itself;
    // everything else maps its inputs into an MS-SMT. Mirrors the
    // branch in Go's tapscript.VirtualTx.
    let (txin, root_hash, root_sum) = if new_asset
        .needs_genesis_witness_for_group()
        || new_asset.has_genesis_witness_for_group()
    {
        virtual_genesis_tx_in(new_asset)?
    } else {
        virtual_tx_in(new_asset, prev_assets)?
    };
    let txout = virtual_tx_out(new_asset)?;

    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    Ok((tx, root_hash, root_sum))
}

/// Creates a per-input copy of the virtual transaction with asset-specific
/// lock time, sequence, and input index.
///
/// Matches Go's `VirtualTxWithInput` in `asset/tx.go`.
pub fn virtual_tx_with_input(
    base_tx: &Transaction,
    lock_time: u64,
    relative_lock_time: u64,
    idx: u32,
    witness: BtcWitness,
) -> Transaction {
    let mut tx = base_tx.clone();
    tx.lock_time = bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(lock_time as u32);
    tx.input[0].previous_output.vout = idx;
    tx.input[0].sequence = Sequence::from_consensus(relative_lock_time as u32);
    tx.input[0].witness = witness;
    tx
}

/// Computes the BIP-341 prevout for the virtual transaction's input.
///
/// The previous output's script is `OP_1 <schnorr_script_key>` and its
/// value is the input asset's amount.
///
/// Matches Go's `InputAssetPrevOut` in `tapscript/tx.go`.
pub fn input_prev_out(input_asset: &Asset) -> Result<TxOut, VirtualTxError> {
    let x_only = XOnlyPublicKey::from_slice(input_asset.script_key.serialized().schnorr_bytes())
        .map_err(|e| VirtualTxError::InvalidKey(e.to_string()))?;

    let script = compute_taproot_script(&x_only.serialize());

    Ok(TxOut {
        value: Amount::from_sat(input_asset.amount),
        script_pubkey: script,
    })
}

/// Computes the BIP-341 prevout for a grouped asset genesis input.
///
/// The previous output's script commits to the tweaked GROUP key (not
/// the script key), enabling group witness validation. Matches Go's
/// `asset.InputGenesisAssetPrevOut` (asset/tx.go).
pub fn input_genesis_prev_out(
    input_asset: &Asset,
) -> Result<TxOut, VirtualTxError> {
    let group_key = input_asset.group_key.as_ref().ok_or_else(|| {
        VirtualTxError::InvalidKey("genesis input has no group key".into())
    })?;

    let x_only =
        XOnlyPublicKey::from_slice(group_key.group_pub_key.schnorr_bytes())
            .map_err(|e| VirtualTxError::InvalidKey(e.to_string()))?;

    Ok(TxOut {
        value: Amount::from_sat(input_asset.amount),
        script_pubkey: compute_taproot_script(&x_only.serialize()),
    })
}

/// Computes the BIP-341 key-spend sighash for a grouped asset genesis
/// virtual transaction, where the prevout commits to the group key.
pub fn input_group_genesis_key_spend_sighash(
    base_virtual_tx: &Transaction,
    new_asset: &Asset,
    sig_hash_type: TapSighashType,
) -> Result<[u8; 32], VirtualTxError> {
    let tx = virtual_tx_with_input(
        base_virtual_tx,
        new_asset.lock_time,
        new_asset.relative_lock_time,
        0,
        BtcWitness::new(),
    );

    let prev_out = input_genesis_prev_out(new_asset)?;
    let prevouts = [prev_out];

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sig_hash_type)
        .map_err(|e| VirtualTxError::SighashError(e.to_string()))?;

    Ok(sighash.to_byte_array())
}

/// Computes the BIP-341 taproot key-spend sighash for a virtual transaction.
///
/// This is the 32-byte message that gets signed with a Schnorr signature.
/// Matches Go's `InputKeySpendSigHash` in `tapscript/tx.go`.
pub fn input_key_spend_sighash(
    base_virtual_tx: &Transaction,
    input_asset: &Asset,
    new_asset: &Asset,
    idx: u32,
    sig_hash_type: TapSighashType,
) -> Result<[u8; 32], VirtualTxError> {
    let tx = virtual_tx_with_input(
        base_virtual_tx,
        new_asset.lock_time,
        new_asset.relative_lock_time,
        idx,
        BtcWitness::new(),
    );

    let prev_out = input_prev_out(input_asset)?;
    let prevouts = [prev_out];

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sig_hash_type)
        .map_err(|e| VirtualTxError::SighashError(e.to_string()))?;

    Ok(sighash.to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: crate::asset::OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    #[test]
    fn test_virtual_tx_in_prevout_deterministic() {
        let hash = NodeHash([0xAA; 32]);
        let out1 = virtual_tx_in_prevout(&hash, 100);
        let out2 = virtual_tx_in_prevout(&hash, 100);
        assert_eq!(out1, out2);

        // Different sum → different prevout.
        let out3 = virtual_tx_in_prevout(&hash, 200);
        assert_ne!(out1, out3);
    }

    #[test]
    fn test_virtual_tx_construction() {
        let genesis = test_genesis();
        let prev_key = SerializedKey([0x02; 33]);
        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(prev_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_id = PrevId {
            out_point: crate::asset::OutPoint {
                txid: [0xBB; 32],
                vout: 0,
            },
            id: genesis.id(),
            script_key: prev_key,
        };

        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset);

        let (tx, root_hash, root_sum) = virtual_tx(&new_asset, &prev_assets).unwrap();

        assert_eq!(tx.version, bitcoin::transaction::Version(2));
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(root_sum, 100);
        assert_ne!(root_hash, NodeHash::EMPTY);

        // Output value should equal the asset amount.
        assert_eq!(tx.output[0].value, Amount::from_sat(100));

        // Output script should be a witness v1 program (P2TR-like).
        assert_eq!(tx.output[0].script_pubkey.len(), 34);
        assert_eq!(tx.output[0].script_pubkey.as_bytes()[0], 0x51); // OP_1
    }

    #[test]
    fn test_virtual_tx_with_input_sets_fields() {
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let modified = virtual_tx_with_input(&tx, 500, 10, 3, BtcWitness::new());
        assert_eq!(
            modified.lock_time,
            bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(500)
        );
        assert_eq!(modified.input[0].previous_output.vout, 3);
        assert_eq!(modified.input[0].sequence, Sequence::from_consensus(10));
    }

    #[test]
    fn test_sighash_computation() {
        let genesis = test_genesis();
        let prev_key = SerializedKey([0x02; 33]);
        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(prev_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_id = PrevId {
            out_point: crate::asset::OutPoint {
                txid: [0xBB; 32],
                vout: 0,
            },
            id: genesis.id(),
            script_key: prev_key,
        };

        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset.clone());

        let (base_tx, _, _) = virtual_tx(&new_asset, &prev_assets).unwrap();

        // Compute sighash — should succeed and be deterministic.
        let sighash1 = input_key_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            TapSighashType::Default,
        )
        .unwrap();

        let sighash2 = input_key_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            TapSighashType::Default,
        )
        .unwrap();

        assert_eq!(sighash1, sighash2);
        assert_ne!(sighash1, [0u8; 32]);
    }

    #[test]
    fn test_sign_and_verify_virtual_tx() {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = 0x01;
        secret[31] = 0x01;
        let sk = SecretKey::from_slice(&secret).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (x_only, _) = keypair.x_only_public_key();

        // Build compressed key from x-only.
        let mut pub_key_bytes = [0u8; 33];
        pub_key_bytes[0] = 0x02;
        pub_key_bytes[1..].copy_from_slice(&x_only.serialize());
        let prev_key = SerializedKey(pub_key_bytes);

        let genesis = test_genesis();
        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(prev_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_id = PrevId {
            out_point: crate::asset::OutPoint { txid: [0xCC; 32], vout: 0 },
            id: genesis.id(),
            script_key: prev_key,
        };

        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset.clone());

        let (base_tx, _, _) = virtual_tx(&new_asset, &prev_assets).unwrap();

        let sighash = input_key_spend_sighash(
            &base_tx,
            &prev_asset,
            &new_asset,
            0,
            TapSighashType::Default,
        )
        .unwrap();

        // Sign and verify.
        let msg = Message::from_digest(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        assert!(secp.verify_schnorr(&sig, &msg, &x_only).is_ok());
    }
}
