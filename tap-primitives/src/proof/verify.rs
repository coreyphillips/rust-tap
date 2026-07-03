// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Proof verification pipeline, mirroring Go's `proof/verifier.go`.
//!
//! Verification is modular — external systems provide implementations of
//! [`HeaderVerifier`], [`MerkleVerifier`], [`GroupVerifier`], and
//! [`ChainLookup`] to plug into the verification context. This allows the
//! proof verification logic to work without depending on a full Bitcoin
//! node or specific chain backend.

use std::collections::{HashMap, HashSet};

use crate::asset::{
    self, Asset, PrevId, SerializedKey, MAX_ASSET_NAME_LENGTH,
};
use crate::commitment::{
    is_similar_tap_commitment_version, CommitmentProof, TapCommitment,
    TapCommitmentVersion, TapscriptPreimage,
};
use crate::crypto::tapscript::taproot_output_key;
use crate::vm;

use super::types::*;
use super::ProofError;

/// Verifies a Bitcoin block header at a given height.
pub trait HeaderVerifier {
    fn verify_header(
        &self,
        header: &BlockHeader,
        height: u32,
    ) -> Result<(), ProofError>;
}

/// Verifies a transaction's inclusion in a block via Merkle proof.
pub trait MerkleVerifier {
    fn verify_merkle_proof(
        &self,
        tx_hash: &[u8; 32],
        proof: &super::tx_merkle::TxMerkleProof,
        merkle_root: &[u8; 32],
    ) -> Result<(), ProofError>;
}

/// Verifies that a group key is known/valid.
pub trait GroupVerifier {
    fn verify_group_key(
        &self,
        group_key: &SerializedKey,
    ) -> Result<(), ProofError>;
}

/// Chain access needed for time lock validation, a simplified version
/// of Go's `asset.ChainLookup`. Only proofs with active lock times need
/// the optional methods; implementations without chain access can rely
/// on the defaults (which fail) and callers can skip time lock
/// validation instead.
pub trait ChainLookup {
    /// Returns the current best block height of the chain.
    fn current_height(&self) -> Result<u32, ProofError>;

    /// Returns the height of the block the given transaction (txid in
    /// internal byte order) confirmed in. Needed for relative lock
    /// times.
    fn tx_block_height(&self, _txid: &[u8; 32]) -> Result<u32, ProofError> {
        Err(ProofError::VerificationFailed(
            "chain lookup does not support tx height lookups".into(),
        ))
    }

    /// Returns the mean timestamp (Unix seconds) of the block at the
    /// given height. Needed for timestamp-based lock times.
    fn mean_block_timestamp(&self, _height: u32) -> Result<u64, ProofError> {
        Err(ProofError::VerificationFailed(
            "chain lookup does not support block timestamps".into(),
        ))
    }
}

/// A [`ChainLookup`] that reports a fixed best height and supports no
/// other queries.
pub struct FixedHeightChainLookup(pub u32);

impl ChainLookup for FixedHeightChainLookup {
    fn current_height(&self) -> Result<u32, ProofError> {
        Ok(self.0)
    }
}

/// Checks whether an asset point (the [`PrevId`] a verified proof
/// produces) is known to be invalid, mirroring Go's
/// `proof.IgnoreChecker` (proof/verifier.go:48).
///
/// This acts as a rejection cache: once an outpoint + asset ID +
/// script key triple has been marked ignored (e.g. via a signed ignore
/// tuple in a universe supply commitment), any proof producing that
/// asset point fails verification.
pub trait IgnoreChecker {
    /// Returns true if the given asset point is known to be invalid.
    /// A false value could mean the asset point is valid, or that it is
    /// unknown to the checker.
    fn is_ignored(&self, prev_id: &PrevId) -> Result<bool, ProofError>;
}

/// An [`IgnoreChecker`] that never ignores anything. Used as the
/// default type parameter of [`VerifierCtx`] so contexts built without
/// an ignore checker keep working unchanged.
pub struct NoIgnoreChecker;

impl IgnoreChecker for NoIgnoreChecker {
    fn is_ignored(&self, _prev_id: &PrevId) -> Result<bool, ProofError> {
        Ok(false)
    }
}

/// Context for proof verification, bundling all external verifiers.
/// Mirrors Go's `proof.VerifierCtx`.
///
/// The optional `ignore_checker` mirrors Go's
/// `VerifierCtx.IgnoreChecker` (an `lfn.Option`): when present, proofs
/// whose resulting asset point is ignored fail verification.
pub struct VerifierCtx<H, M, G, C, I = NoIgnoreChecker>
where
    H: HeaderVerifier,
    M: MerkleVerifier,
    G: GroupVerifier,
    C: ChainLookup,
    I: IgnoreChecker,
{
    pub header_verifier: H,
    pub merkle_verifier: M,
    pub group_verifier: G,
    pub chain_lookup: C,
    pub ignore_checker: Option<I>,
}

impl<H, M, G, C> VerifierCtx<H, M, G, C, NoIgnoreChecker>
where
    H: HeaderVerifier,
    M: MerkleVerifier,
    G: GroupVerifier,
    C: ChainLookup,
{
    /// Creates a verifier context without an ignore checker.
    pub fn new(
        header_verifier: H,
        merkle_verifier: M,
        group_verifier: G,
        chain_lookup: C,
    ) -> Self {
        VerifierCtx {
            header_verifier,
            merkle_verifier,
            group_verifier,
            chain_lookup,
            ignore_checker: None,
        }
    }

    /// Attaches an ignore checker to this context.
    pub fn with_ignore_checker<I: IgnoreChecker>(
        self,
        ignore_checker: I,
    ) -> VerifierCtx<H, M, G, C, I> {
        VerifierCtx {
            header_verifier: self.header_verifier,
            merkle_verifier: self.merkle_verifier,
            group_verifier: self.group_verifier,
            chain_lookup: self.chain_lookup,
            ignore_checker: Some(ignore_checker),
        }
    }
}

/// Options controlling single-proof verification, mirroring Go's
/// `proofVerificationParams` (proof/verifier.go:943).
#[derive(Clone, Debug, Default)]
pub struct ProofVerificationOptions {
    /// Challenge bytes used when verifying an ownership proof's
    /// challenge witness.
    pub challenge_bytes: Option<[u8; 32]>,
    /// Skips block header and tx merkle proof verification.
    pub skip_chain_verification: bool,
    /// Skips lock time validation.
    pub skip_time_lock_validation: bool,
}

fn verify_err(msg: impl Into<String>) -> ProofError {
    ProofError::VerificationFailed(msg.into())
}

// ---------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------

/// Returns whether the given prevout is spent by the given transaction,
/// mirroring Go's `TxSpendsPrevOut` (proof/util.go:50).
pub fn tx_spends_prev_out(
    tx: &bitcoin::Transaction,
    prev_out: &asset::OutPoint,
) -> bool {
    tx.input.iter().any(|txin| {
        let txid: &[u8; 32] = txin.previous_output.txid.as_ref();
        *txid == prev_out.txid && txin.previous_output.vout == prev_out.vout
    })
}

/// Returns true if the script is a pay-to-taproot output script.
fn is_pay_to_taproot(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

/// Extracts the 32-byte x-only taproot output key from the output at
/// `output_index`, mirroring Go's `ExtractTaprootKey` (proof/util.go).
fn extract_taproot_key(
    tx: &bitcoin::Transaction,
    output_index: u32,
) -> Result<[u8; 32], ProofError> {
    let out = tx
        .output
        .get(output_index as usize)
        .ok_or_else(|| verify_err("invalid output index"))?;
    let script = out.script_pubkey.as_bytes();
    if !is_pay_to_taproot(script) {
        return Err(verify_err("output is not a P2TR script"));
    }
    Ok(script[2..34].try_into().expect("32 bytes"))
}

/// Validates an asset name (genesis tag), mirroring Go's
/// `asset.ValidateAssetName` (asset/asset.go).
fn validate_asset_name(name: &str) -> Result<(), ProofError> {
    if name.is_empty() {
        return Err(verify_err("asset name cannot be empty"));
    }
    if name.len() > MAX_ASSET_NAME_LENGTH {
        return Err(verify_err(format!(
            "asset name cannot exceed {} bytes",
            MAX_ASSET_NAME_LENGTH
        )));
    }
    // Rust strings are always valid UTF-8; check printability with
    // Go's unicode.IsPrint semantics (categories L, M, N, P, S plus
    // the ASCII space), not just control characters: format characters
    // like zero width spaces and non-ASCII whitespace are rejected by
    // Go and must be rejected here too, or we mint assets (and asset
    // IDs) that Go nodes refuse.
    if !name.chars().all(is_go_print) {
        return Err(verify_err(
            "asset name cannot contain unprintable character",
        ));
    }
    if name.trim().is_empty() {
        return Err(verify_err("asset name cannot contain only spaces"));
    }
    Ok(())
}

/// Mirrors Go's `unicode.IsPrint`: true for letters, marks, numbers,
/// punctuation, symbols, and the ASCII space.
///
/// Unicode versions may differ slightly between Go's bundled tables and
/// the unicode-general-category crate for newly assigned code points;
/// both reject unassigned, control, format, surrogate, private use,
/// and non-ASCII separator characters.
fn is_go_print(c: char) -> bool {
    use unicode_general_category::{get_general_category, GeneralCategory};

    if c == ' ' {
        return true;
    }
    matches!(
        get_general_category(c),
        GeneralCategory::UppercaseLetter
            | GeneralCategory::LowercaseLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
            | GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
            | GeneralCategory::EnclosingMark
            | GeneralCategory::DecimalNumber
            | GeneralCategory::LetterNumber
            | GeneralCategory::OtherNumber
            | GeneralCategory::ConnectorPunctuation
            | GeneralCategory::DashPunctuation
            | GeneralCategory::OpenPunctuation
            | GeneralCategory::ClosePunctuation
            | GeneralCategory::InitialPunctuation
            | GeneralCategory::FinalPunctuation
            | GeneralCategory::OtherPunctuation
            | GeneralCategory::MathSymbol
            | GeneralCategory::CurrencySymbol
            | GeneralCategory::ModifierSymbol
            | GeneralCategory::OtherSymbol
    )
}

/// Returns true if the optional preimage is absent or empty, mirroring
/// Go's `TapscriptPreimage.IsEmpty` on possibly-nil receivers.
fn preimage_is_empty(p: &Option<TapscriptPreimage>) -> bool {
    match p {
        None => true,
        Some(p) => p.is_empty(),
    }
}

/// Computes the sibling hash of an optional tapscript preimage.
fn sibling_hash(
    preimage: Option<&TapscriptPreimage>,
) -> Result<Option<[u8; 32]>, ProofError> {
    match preimage {
        None => Ok(None),
        Some(p) => p
            .tap_hash()
            .map(Some)
            .map_err(|e| verify_err(e.to_string())),
    }
}

// ---------------------------------------------------------------------
// Taproot key derivation (Go proof/taproot.go)
// ---------------------------------------------------------------------

/// The set of candidate (x-only taproot output key, commitment) pairs
/// derived from a taproot proof, mirroring Go's `ProofCommitmentKeys`.
type ProofCommitmentKeys = Vec<([u8; 32], TapCommitment)>;

/// Derives the possible taproot output keys backing a Taproot Asset
/// commitment, mirroring Go's `deriveCommitmentKeys`
/// (proof/taproot.go:442). Go derives one key for the proof's
/// commitment version and one for the downgraded (V0) commitment; a
/// match on either is accepted.
fn derive_commitment_keys(
    root: crate::mssmt::BranchNode,
    version: TapCommitmentVersion,
    internal_key: &SerializedKey,
    sibling_preimage: Option<&TapscriptPreimage>,
) -> Result<ProofCommitmentKeys, ProofError> {
    let sibling = sibling_hash(sibling_preimage)?;

    let commitment = TapCommitment::from_root(version, root);
    let key = taproot_output_key(
        internal_key,
        &commitment.tapscript_root(sibling.as_ref()),
    )
    .map_err(verify_err)?;

    let downgraded = commitment.downgrade();
    let downgraded_key = taproot_output_key(
        internal_key,
        &downgraded.tapscript_root(sibling.as_ref()),
    )
    .map_err(verify_err)?;

    // Later entries win on key collisions in Go's map semantics; when
    // the versions coincide (proof version already V0) both entries are
    // identical, so a Vec is equivalent.
    Ok(vec![(key, commitment), (downgraded_key, downgraded)])
}

/// Derives the candidate taproot output keys by interpreting the proof
/// as an asset inclusion proof, mirroring Go's
/// `TaprootProof.DeriveByAssetInclusion` (proof/taproot.go:349).
fn derive_by_asset_inclusion(
    tp: &TaprootProof,
    asset: &Asset,
) -> Result<ProofCommitmentKeys, ProofError> {
    let cp = match (&tp.commitment_proof, &tp.tapscript_proof) {
        (Some(cp), None) => cp,
        _ => return Err(verify_err("invalid Taproot Asset commitment proof")),
    };

    // If this is an asset with a split commitment, the inclusion proof
    // is verified without that information, as the receiver's output
    // was created without it.
    let mut asset_copy;
    let asset = if asset.has_split_commitment_witness() {
        asset_copy = asset.clone();
        asset_copy.prev_witnesses[0].split_commitment = None;
        &asset_copy
    } else {
        asset
    };

    let asset_proof = cp
        .asset_proof
        .as_ref()
        .ok_or_else(|| verify_err("missing asset proof"))?;

    let ack = crate::commitment::asset_commitment_key(
        &asset.id(),
        asset.script_key.serialized(),
        asset.group_key.is_some(),
    );
    let leaf = crate::commitment::asset_leaf(asset);

    // The asset commitment is rebuilt from the proof's own tap key
    // (Go's AssetCommitment{TapKey: p.AssetProof.TapKey}).
    let root = cp
        .derive_by_asset_inclusion(&ack, &leaf, &asset_proof.tap_key)
        .map_err(|e| verify_err(e.to_string()))?;

    derive_commitment_keys(
        root,
        cp.taproot_asset_proof.version,
        &tp.internal_key,
        cp.tap_sibling_preimage.as_ref(),
    )
}

/// Derives the candidate taproot output keys by interpreting the proof
/// as an asset exclusion proof, mirroring Go's
/// `TaprootProof.DeriveByAssetExclusion` (proof/taproot.go:395).
fn derive_by_asset_exclusion(
    tp: &TaprootProof,
    asset_commitment_key: [u8; 32],
    tap_commitment_key: [u8; 32],
) -> Result<ProofCommitmentKeys, ProofError> {
    let cp = match (&tp.commitment_proof, &tp.tapscript_proof) {
        (Some(cp), None) => cp,
        _ => return Err(verify_err("invalid Taproot Asset commitment proof")),
    };

    let root = match &cp.asset_proof {
        // No asset proof: prove that no asset commitment exists at the
        // asset's tap commitment key.
        None => cp
            .derive_by_commitment_exclusion(&tap_commitment_key)
            .map_err(|e| verify_err(e.to_string()))?,

        // Asset proof present: the tree contains the asset ID sub-tree
        // but the specific asset is not included.
        Some(asset_proof) => cp
            .derive_by_asset_exclusion(
                &asset_commitment_key,
                &asset_proof.tap_key,
            )
            .map_err(|e| verify_err(e.to_string()))?,
    };

    derive_commitment_keys(
        root,
        cp.taproot_asset_proof.version,
        &tp.internal_key,
        cp.tap_sibling_preimage.as_ref(),
    )
}

/// Derives the expected taproot key from a tapscript proof, mirroring
/// Go's `TapscriptProof.DeriveTaprootKeys` (proof/taproot.go:515).
fn derive_by_tapscript_proof(
    tp: &TaprootProof,
) -> Result<[u8; 32], ProofError> {
    let ts = match (&tp.commitment_proof, &tp.tapscript_proof) {
        (None, Some(ts)) => ts,
        _ => return Err(verify_err("invalid tapscript proof")),
    };

    let p1_empty = preimage_is_empty(&ts.tap_preimage_1);
    let p2_empty = preimage_is_empty(&ts.tap_preimage_2);

    let p1_type = ts.tap_preimage_1.as_ref().map(|p| p.sibling_type);
    let p2_type = ts.tap_preimage_2.as_ref().map(|p| p.sibling_type);

    let tapscript_root: Vec<u8> = match (p1_empty, p2_empty) {
        // Two preimages: leaf+leaf, branch+branch, or leaf+branch (in
        // that order only, matching Go's case table).
        (false, false) => {
            let valid_combo = matches!(
                (p1_type, p2_type),
                (Some(0), Some(0)) | (Some(1), Some(1)) | (Some(0), Some(1))
            );
            if !valid_combo {
                return Err(verify_err("invalid tapscript pre-images"));
            }
            let h1 = sibling_hash(ts.tap_preimage_1.as_ref())?
                .expect("non-empty preimage");
            let h2 = sibling_hash(ts.tap_preimage_2.as_ref())?
                .expect("non-empty preimage");
            crate::crypto::tapscript::tap_branch_hash(&h1, &h2).to_vec()
        }

        // Single leaf preimage.
        (false, true) if p1_type == Some(0) => {
            sibling_hash(ts.tap_preimage_1.as_ref())?
                .expect("non-empty preimage")
                .to_vec()
        }

        // BIP-0086 output committing to no root hash.
        _ if ts.bip86 => Vec::new(),

        _ => return Err(verify_err("invalid tapscript pre-images")),
    };

    taproot_output_key(&tp.internal_key, &tapscript_root)
        .map_err(verify_err)
}

/// Verifies a `TaprootProof` for inclusion or exclusion of an asset,
/// mirroring Go's `verifyTaprootProof` (proof/verifier.go:161). If the
/// proof is an inclusion proof (or an exclusion proof with a commitment
/// proof), the matched `TapCommitment` is returned; tapscript proofs
/// return `None`.
fn verify_taproot_proof(
    anchor: &bitcoin::Transaction,
    tp: &TaprootProof,
    asset: &Asset,
    inclusion: bool,
) -> Result<Option<TapCommitment>, ProofError> {
    // Extract the final taproot key from the on-chain output.
    let expected_key = extract_taproot_key(anchor, tp.output_index)?;

    let derived_keys: ProofCommitmentKeys = if inclusion {
        derive_by_asset_inclusion(tp, asset)?
    } else if tp.commitment_proof.is_some() {
        let ack = crate::commitment::asset_commitment_key(
            &asset.id(),
            asset.script_key.serialized(),
            asset.group_key.is_some(),
        );
        let tck = crate::commitment::tap_commitment_key(
            &asset.id(),
            asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
        );
        derive_by_asset_exclusion(tp, ack, tck)?
    } else if tp.tapscript_proof.is_some() {
        let derived_key = derive_by_tapscript_proof(tp)?;
        if derived_key == expected_key {
            return Ok(None);
        }
        Vec::new()
    } else {
        Vec::new()
    };

    // One of the derived keys must match the expected key. Iterate in
    // reverse so the downgraded (later) entry wins on identical keys,
    // matching Go's map overwrite semantics.
    for (derived_key, commitment) in derived_keys.into_iter().rev() {
        if derived_key == expected_key {
            return Ok(Some(commitment));
        }
    }

    Err(verify_err(format!(
        "invalid taproot proof: derived key mismatch, output_index={}",
        tp.output_index
    )))
}

// ---------------------------------------------------------------------
// STXO proofs (Go proof/verifier.go:135-569)
// ---------------------------------------------------------------------

/// Tracks pending STXO proofs per P2TR output index, mirroring Go's
/// `P2TROutputsSTXOs`.
type P2trOutputsStxos = HashMap<u32, HashSet<SerializedKey>>;

/// Creates a new proof for an STXO by reusing the base proof while
/// replacing the commitment proof pair with the STXO entry, mirroring
/// Go's `MakeSTXOProof` (proof/verifier.go:551).
fn make_stxo_proof(
    base_proof: &TaprootProof,
    stxo_proof: &CommitmentProof,
) -> Result<TaprootProof, ProofError> {
    let base_cp = base_proof
        .commitment_proof
        .as_ref()
        .ok_or_else(|| verify_err("missing commitment proof"))?;

    Ok(TaprootProof {
        output_index: base_proof.output_index,
        internal_key: base_proof.internal_key,
        commitment_proof: Some(CommitmentProof {
            asset_proof: stxo_proof.asset_proof.clone(),
            taproot_asset_proof: stxo_proof.taproot_asset_proof.clone(),
            tap_sibling_preimage: base_cp.tap_sibling_preimage.clone(),
            stxo_proofs: Default::default(),
            unknown_odd_types: stxo_proof.unknown_odd_types.clone(),
        }),
        tapscript_proof: base_proof.tapscript_proof.clone(),
        unknown_odd_types: base_proof.unknown_odd_types.clone(),
    })
}

/// Verifies a set of STXO proofs, mirroring Go's `verifySTXOProofSet`
/// (proof/verifier.go:513). Correctly validated proofs are removed from
/// `p2tr_outputs`.
fn verify_stxo_proof_set(
    anchor: &bitcoin::Transaction,
    base_proof: &TaprootProof,
    asset_map: &HashMap<SerializedKey, Asset>,
    p2tr_outputs: &mut P2trOutputsStxos,
    inclusion: bool,
) -> Result<(), ProofError> {
    let cp = base_proof
        .commitment_proof
        .as_ref()
        .ok_or_else(|| verify_err("missing commitment proof"))?;

    for (key, stxo_proof) in &cp.stxo_proofs {
        let stxo_asset = asset_map.get(key).ok_or_else(|| {
            verify_err(format!(
                "missing STXO asset for key {}",
                crate::hex::encode(key.as_bytes())
            ))
        })?;

        let combined = make_stxo_proof(base_proof, stxo_proof)?;
        verify_taproot_proof(anchor, &combined, stxo_asset, inclusion)
            .map_err(|e| {
                verify_err(format!("error verifying STXO proof: {}", e))
            })?;

        let out_idx = combined.output_index;
        if let Some(set) = p2tr_outputs.get_mut(&out_idx) {
            set.remove(key);
            if set.is_empty() {
                p2tr_outputs.remove(&out_idx);
            }
        }
    }

    Ok(())
}

/// Builds the map of expected STXO assets (spent-asset markers keyed by
/// their burn-derived script keys) for the given output asset.
fn stxo_asset_map(
    out_asset: &Asset,
) -> Result<HashMap<SerializedKey, Asset>, ProofError> {
    let stxo_assets = asset::collect_stxo(out_asset)
        .map_err(|e| verify_err(e.to_string()))?;
    Ok(stxo_assets
        .into_iter()
        .map(|a| (*a.script_key.serialized(), a))
        .collect())
}

// ---------------------------------------------------------------------
// Per-proof verification pieces (Go proof/verifier.go)
// ---------------------------------------------------------------------

impl Proof {
    /// Verifies the inclusion proof, mirroring Go's
    /// `Proof.verifyInclusionProof` (proof/verifier.go:242).
    fn verify_inclusion_proof(&self) -> Result<TapCommitment, ProofError> {
        // We always check the v0 inclusion proof.
        let v0_commitment = verify_taproot_proof(
            &self.anchor_tx.0,
            &self.inclusion_proof,
            &self.asset,
            true,
        )
        .map_err(|e| {
            verify_err(format!("error verifying v0 inclusion proof: {}", e))
        })?
        .ok_or_else(|| verify_err("inclusion proof has no commitment"))?;

        // If this is a v1 proof, we need STXO proofs when the asset is
        // a transfer root.
        let need_stxo_proofs =
            self.is_version_v1() && self.asset.is_transfer_root();
        let has_stxo_proofs = self
            .inclusion_proof
            .commitment_proof
            .as_ref()
            .map(|cp| !cp.stxo_proofs.is_empty())
            .unwrap_or(false);

        if need_stxo_proofs && !has_stxo_proofs {
            return Err(verify_err("missing STXO input proofs"));
        }

        // Skip STXO validation when not needed or absent; verify them
        // when present even if not strictly needed.
        if !self.asset.is_transfer_root() || !has_stxo_proofs {
            return Ok(v0_commitment);
        }

        let out_idx = self.inclusion_proof.output_index;
        let asset_map = stxo_asset_map(&self.asset)?;
        let mut p2tr_outputs: P2trOutputsStxos = HashMap::new();
        p2tr_outputs.insert(out_idx, asset_map.keys().copied().collect());

        verify_stxo_proof_set(
            &self.anchor_tx.0,
            &self.inclusion_proof,
            &asset_map,
            &mut p2tr_outputs,
            true,
        )
        .map_err(|e| {
            verify_err(format!("error verifying v1 inclusion proof: {}", e))
        })?;

        if !p2tr_outputs.is_empty() {
            return Err(verify_err(
                "missing STXO input proof: missing inclusion proof",
            ));
        }

        Ok(v0_commitment)
    }

    /// Decodes the split root asset carried in the asset's first
    /// witness' split commitment.
    fn split_root_asset(&self) -> Result<Asset, ProofError> {
        let witness = self
            .asset
            .prev_witnesses
            .first()
            .ok_or_else(|| verify_err("asset has no witnesses"))?;
        let split = witness
            .split_commitment
            .as_ref()
            .ok_or_else(|| verify_err("asset has no split commitment"))?;
        crate::encoding::asset::decode_asset(&split.root_asset)
            .map_err(|e| verify_err(format!("invalid root asset: {}", e)))
    }

    /// Verifies the split root proof, mirroring Go's
    /// `Proof.verifySplitRootProof` (proof/verifier.go:314).
    fn verify_split_root_proof(&self) -> Result<(), ProofError> {
        let root_asset = self.split_root_asset()?;
        let split_root_proof = self
            .split_root_proof
            .as_ref()
            .ok_or_else(|| verify_err("missing split root proof"))?;

        verify_taproot_proof(
            &self.anchor_tx.0,
            split_root_proof,
            &root_asset,
            true,
        )?;
        Ok(())
    }

    /// Verifies all exclusion proofs, mirroring Go's
    /// `Proof.verifyExclusionProofs` (proof/verifier.go:324). Returns
    /// the common commitment version of the exclusion proofs, or `None`
    /// if all exclusion proofs were tapscript proofs (or no other P2TR
    /// outputs exist).
    fn verify_exclusion_proofs(
        &self,
    ) -> Result<Option<TapCommitmentVersion>, ProofError> {
        // Gather all P2TR outputs in the on-chain transaction.
        let mut p2tr_outputs: HashSet<u32> = HashSet::new();
        for (i, out) in self.anchor_tx.0.output.iter().enumerate() {
            let i = i as u32;
            if i == self.inclusion_proof.output_index {
                continue;
            }
            if is_pay_to_taproot(out.script_pubkey.as_bytes()) {
                p2tr_outputs.insert(i);
            }
        }

        // Nothing to check, return early.
        if p2tr_outputs.is_empty() {
            return Ok(None);
        }

        let commit_versions =
            self.verify_v0_exclusion_proofs(p2tr_outputs.clone())?;

        // No asset commitments present in any excluded output.
        if commit_versions.is_empty() {
            return Ok(None);
        }

        let need_stxo_proofs =
            self.is_version_v1() && self.asset.is_transfer_root();
        let has_stxo_proofs = self
            .exclusion_proofs
            .first()
            .and_then(|ep| ep.commitment_proof.as_ref())
            .map(|cp| !cp.stxo_proofs.is_empty())
            .unwrap_or(false);

        if need_stxo_proofs && !has_stxo_proofs {
            return Err(verify_err("missing STXO exclusion proofs"));
        }

        if !self.asset.is_transfer_root() || !has_stxo_proofs {
            return assert_version_consistency(&commit_versions);
        }

        self.verify_v1_exclusion_proofs(p2tr_outputs).map_err(|e| {
            verify_err(format!("error verifying v1 exclusion proof: {}", e))
        })?;

        assert_version_consistency(&commit_versions)
    }

    /// Verifies all V0 exclusion proofs, mirroring Go's
    /// `Proof.verifyV0ExclusionProofs` (proof/verifier.go:398). Returns
    /// the commitment versions of outputs that carried Taproot Asset
    /// commitments.
    fn verify_v0_exclusion_proofs(
        &self,
        mut p2tr_outputs: HashSet<u32>,
    ) -> Result<Vec<(u32, TapCommitmentVersion)>, ProofError> {
        let mut commit_versions = Vec::new();

        for exclusion_proof in &self.exclusion_proofs {
            let derived_commitment = verify_taproot_proof(
                &self.anchor_tx.0,
                exclusion_proof,
                &self.asset,
                false,
            )
            .map_err(|e| {
                verify_err(format!(
                    "error verifying exclusion proof for output {}: {}",
                    exclusion_proof.output_index, e
                ))
            })?;

            p2tr_outputs.remove(&exclusion_proof.output_index);

            if let Some(commitment) = derived_commitment {
                commit_versions.push((
                    exclusion_proof.output_index,
                    commitment.version,
                ));
            }
        }

        // Any outputs left in the set are missing exclusion proofs.
        if !p2tr_outputs.is_empty() {
            let mut missing: Vec<u32> =
                p2tr_outputs.into_iter().collect();
            missing.sort_unstable();
            return Err(ProofError::InvalidExclusionProof(format!(
                "missing exclusion proofs for outputs: {:?}",
                missing
            )));
        }

        Ok(commit_versions)
    }

    /// Verifies all V1 (STXO) exclusion proofs, mirroring Go's
    /// `Proof.verifyV1ExclusionProofs` (proof/verifier.go:456).
    fn verify_v1_exclusion_proofs(
        &self,
        p2tr_outputs: HashSet<u32>,
    ) -> Result<(), ProofError> {
        let asset_map = stxo_asset_map(&self.asset)?;

        let mut p2tr_outputs_stxos: P2trOutputsStxos = p2tr_outputs
            .into_iter()
            .map(|idx| (idx, asset_map.keys().copied().collect()))
            .collect();

        for exclusion_proof in &self.exclusion_proofs {
            // Outputs without any assets are covered by the (already
            // verified) tapscript proofs.
            if exclusion_proof.tapscript_proof.is_some() {
                p2tr_outputs_stxos.remove(&exclusion_proof.output_index);
                continue;
            }

            verify_stxo_proof_set(
                &self.anchor_tx.0,
                exclusion_proof,
                &asset_map,
                &mut p2tr_outputs_stxos,
                false,
            )?;
        }

        if !p2tr_outputs_stxos.is_empty() {
            return Err(verify_err("missing STXO exclusion proofs"));
        }

        Ok(())
    }

    /// Verifies the inclusion, split root, and exclusion proofs,
    /// mirroring Go's `Proof.VerifyProofs` (proof/verifier.go:1209).
    pub fn verify_proofs(&self) -> Result<TapCommitment, ProofError> {
        let tap_commitment = self.verify_inclusion_proof().map_err(|e| {
            ProofError::InvalidInclusionProof(e.to_string())
        })?;

        if self.asset.has_split_commitment_witness() {
            if self.split_root_proof.is_none() {
                return Err(verify_err("missing split root proof"));
            }
            self.verify_split_root_proof()?;
        }

        let exclusion_commit_version = self.verify_exclusion_proofs()?;

        // If all exclusion proofs were tapscript proofs, no version
        // checking is needed.
        let Some(exclusion_version) = exclusion_commit_version else {
            return Ok(tap_commitment);
        };

        // The inclusion proof must have a similar version to all
        // exclusion proofs.
        if !is_similar_tap_commitment_version(
            Some(&tap_commitment.version),
            Some(&exclusion_version),
        ) {
            return Err(verify_err(format!(
                "mixed commitment versions, inclusion {:?}, exclusion {:?}",
                tap_commitment.version, exclusion_version
            )));
        }

        Ok(tap_commitment)
    }

    /// Verifies the genesis reveal against the asset ID and proof
    /// details, mirroring Go's `Proof.verifyGenesisReveal`
    /// (proof/verifier.go:767).
    fn verify_genesis_reveal(&self) -> Result<(), ProofError> {
        let reveal = self
            .genesis_reveal
            .as_ref()
            .ok_or_else(|| verify_err("genesis reveal required"))?;

        if reveal.first_prev_out != self.prev_out {
            return Err(ProofError::GenesisPrevOutMismatch);
        }

        // If this asset has an empty meta reveal, then the meta hash
        // must be empty. Otherwise, the meta hash must match the meta
        // reveal.
        let zero_meta = [0u8; 32];
        if self.meta_reveal.is_none() && reveal.meta_hash != zero_meta {
            return Err(verify_err("genesis meta reveal required"));
        }

        let proof_meta = self
            .meta_reveal
            .as_ref()
            .map(|m| m.meta_hash())
            .unwrap_or(zero_meta);

        if reveal.meta_hash != proof_meta {
            return Err(ProofError::MetaHashMismatch);
        }

        if reveal.output_index != self.inclusion_proof.output_index {
            return Err(verify_err(
                "genesis reveal output index mismatch",
            ));
        }

        // The genesis reveal determines the ID of an asset; since the
        // asset ID commits to all fields of the genesis, this covers
        // the remaining fields.
        if reveal.id() != self.asset.id() {
            return Err(ProofError::GenesisMismatch);
        }

        Ok(())
    }

    /// Verifies that the group key reveal derives the asset's group
    /// key, mirroring Go's `Proof.verifyGroupKeyReveal`
    /// (proof/verifier.go:824). For V0 reveals the full derivation is
    /// checked; for V1 reveals the full Go derivation is mirrored:
    /// the reveal's tapscript tree is structurally validated against
    /// the asset ID (asset/group_key.go, `GroupPubKeyV1` ->
    /// `GroupKeyRevealTapscript.Validate`) before the taproot tweak
    /// of the internal key with the tapscript root is checked.
    fn verify_group_key_reveal(&self) -> Result<(), ProofError> {
        use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};

        let group_key = self
            .asset
            .group_key
            .as_ref()
            .ok_or_else(|| verify_err("group key required"))?;
        let reveal = self
            .group_key_reveal
            .as_ref()
            .ok_or_else(|| verify_err("group key reveal required"))?;

        let asset_id = self.asset.id();
        let secp = Secp256k1::new();

        let revealed_key: PublicKey = match reveal {
            // V0 (Go's GroupKeyRevealV0.GroupPubKey,
            // asset/group_key.go:969):
            //   internal_key = raw_key + asset_id*G
            //   group_key = TapTweak(internal_key, tapscript_root)
            asset::GroupKeyReveal::V0(v0) => {
                let raw = PublicKey::from_slice(v0.raw_key.as_bytes())
                    .map_err(|e| {
                        verify_err(format!(
                            "group reveal raw key invalid: {}",
                            e
                        ))
                    })?;
                let single_tweak =
                    Scalar::from_be_bytes(*asset_id.as_bytes()).map_err(
                        |e| verify_err(format!("invalid genesis tweak: {}", e)),
                    )?;
                let internal =
                    raw.add_exp_tweak(&secp, &single_tweak).map_err(|e| {
                        verify_err(format!("group key tweak failed: {}", e))
                    })?;

                let tap_tweak = match v0.tapscript_root.len() {
                    0 | 32 => v0.tapscript_root.as_slice(),
                    _ => {
                        return Err(verify_err(
                            "tapscript tweaks must be 32 bytes",
                        ))
                    }
                };

                let internal_serialized =
                    crate::asset::SerializedKey(internal.serialize());
                // The full (parity-carrying) output key, matching Go's
                // ComputeTaprootOutputKey result.
                full_taproot_output_key(
                    &secp,
                    &internal_serialized,
                    tap_tweak,
                )?
            }

            // V1 (Go's GroupKeyRevealV1.GroupPubKey,
            // asset/group_key.go:838): validates the reveal's
            // tapscript tree against the asset ID, then applies the
            // taproot tweak of the internal key with the root.
            asset::GroupKeyReveal::V1(v1) => {
                v1.group_pub_key(&asset_id).map_err(|e| {
                    verify_err(format!(
                        "group key reveal invalid: {}",
                        e
                    ))
                })?
            }
        };

        // Make sure the derived key matches what we expect. Go compares
        // full public keys (X and Y).
        if revealed_key.serialize() != group_key.group_pub_key.0 {
            return Err(verify_err(
                "group key reveal doesn't match group key",
            ));
        }

        Ok(())
    }
}

/// Computes the full (compressed, parity-carrying) taproot output key
/// for the given internal key and tap tweak, matching Go's
/// `txscript.ComputeTaprootOutputKey` before schnorr serialization.
fn full_taproot_output_key(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    internal_key: &SerializedKey,
    merkle_root: &[u8],
) -> Result<bitcoin::secp256k1::PublicKey, ProofError> {
    use bitcoin::secp256k1::{PublicKey, Scalar, XOnlyPublicKey};
    use bitcoin_hashes::{sha256, Hash, HashEngine};

    let x_only = XOnlyPublicKey::from_slice(internal_key.schnorr_bytes())
        .map_err(|e| verify_err(format!("invalid internal key: {}", e)))?;

    let tag_hash = sha256::Hash::hash(b"TapTweak").to_byte_array();
    let mut engine = sha256::HashEngine::default();
    engine.input(&tag_hash);
    engine.input(&tag_hash);
    engine.input(&x_only.serialize());
    engine.input(merkle_root);
    let tweak = sha256::Hash::from_engine(engine).to_byte_array();

    let scalar = Scalar::from_be_bytes(tweak)
        .map_err(|e| verify_err(format!("invalid tap tweak: {}", e)))?;
    let (tweaked, parity) = x_only
        .add_tweak(secp, &scalar)
        .map_err(|e| verify_err(format!("tweak failed: {}", e)))?;

    Ok(PublicKey::from_x_only_public_key(tweaked, parity))
}

// ---------------------------------------------------------------------
// Time lock validation (Go vm/vm.go checkLockTime/checkRelativeLockTime)
// ---------------------------------------------------------------------

/// Bitcoin's threshold above which a lock time is interpreted as a Unix
/// timestamp instead of a block height.
const LOCK_TIME_THRESHOLD: u64 = 500_000_000;

/// Sequence flag denoting that relative lock times are disabled.
const SEQUENCE_LOCK_TIME_DISABLED: u64 = 1 << 31;

/// Sequence flag denoting a time-based (rather than height-based)
/// relative lock time.
const SEQUENCE_LOCK_TIME_IS_SECONDS: u64 = 1 << 22;

/// Mask extracting the relative lock time value from a sequence.
const SEQUENCE_LOCK_TIME_MASK: u64 = 0x0000_ffff;

/// Validates the lock times of the given asset against the anchor block
/// height, a simplified mirror of Go's `checkLockTime` and
/// `checkRelativeLockTime` (vm/vm.go:560+).
fn check_time_locks<C: ChainLookup>(
    new_asset: &Asset,
    block_height: u32,
    chain_lookup: &C,
) -> Result<(), ProofError> {
    // Prefer the anchor block height (Go passes vm.WithBlockHeight); if
    // it is unset, fall back to the chain's current height.
    let block_height = if block_height != 0 {
        block_height
    } else {
        chain_lookup.current_height()?
    };

    // Absolute lock time.
    if new_asset.lock_time != 0 {
        if new_asset.lock_time > LOCK_TIME_THRESHOLD {
            // Timestamp-based lock: compare against the block's mean
            // timestamp.
            let mean_time = chain_lookup.mean_block_timestamp(block_height)?;
            if mean_time < new_asset.lock_time {
                return Err(verify_err(format!(
                    "unfinalized asset: block_time={}, min_time={}",
                    mean_time, new_asset.lock_time
                )));
            }
        } else if (block_height as u64) < new_asset.lock_time {
            return Err(verify_err(format!(
                "unfinalized asset: block_height={}, lock_time={}",
                block_height, new_asset.lock_time
            )));
        }
    }

    // Relative lock time.
    if new_asset.relative_lock_time != 0 {
        let sequence = new_asset.relative_lock_time;

        // Relative time locks disabled for this input.
        if sequence & SEQUENCE_LOCK_TIME_DISABLED
            == SEQUENCE_LOCK_TIME_DISABLED
        {
            return Ok(());
        }

        let relative_lock = sequence & SEQUENCE_LOCK_TIME_MASK;

        for witness in &new_asset.prev_witnesses {
            let Some(prev_id) = witness.prev_id.as_ref() else {
                continue;
            };
            let input_height =
                chain_lookup.tx_block_height(&prev_id.out_point.txid)?;

            if sequence & SEQUENCE_LOCK_TIME_IS_SECONDS
                == SEQUENCE_LOCK_TIME_IS_SECONDS
            {
                // Seconds-based relative lock: needs median times.
                let prev_height = input_height.saturating_sub(1);
                let in_median =
                    chain_lookup.mean_block_timestamp(prev_height)?;
                let block_median =
                    chain_lookup.mean_block_timestamp(block_height)?;
                // BIP-68 granularity: 512-second units.
                let lock_seconds = (relative_lock << 9).saturating_sub(1);
                if block_median < in_median.saturating_add(lock_seconds) {
                    return Err(verify_err(
                        "unfinalized asset: relative time lock not met",
                    ));
                }
            } else {
                // Height-based relative lock.
                let min_height =
                    (input_height as u64).saturating_add(relative_lock);
                if (block_height as u64) < min_height {
                    return Err(verify_err(format!(
                        "unfinalized asset: block_height={}, requires {}",
                        block_height, min_height
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Returns true if the asset carries an active CLTV/CSV lock time,
/// mirroring Go's `assetUsesTimeLock` (proof/verifier.go:1492).
fn asset_uses_time_lock(a: &Asset) -> bool {
    if a.lock_time != 0 {
        return true;
    }
    if a.relative_lock_time == 0 {
        return false;
    }
    a.relative_lock_time & SEQUENCE_LOCK_TIME_DISABLED
        != SEQUENCE_LOCK_TIME_DISABLED
}

// ---------------------------------------------------------------------
// Version consistency (Go proof/verifier.go:573)
// ---------------------------------------------------------------------

/// Verifies all Taproot Asset commitment versions match, mirroring Go's
/// `assertVersionConsistency`.
fn assert_version_consistency(
    versions: &[(u32, TapCommitmentVersion)],
) -> Result<Option<TapCommitmentVersion>, ProofError> {
    let first_version = versions
        .first()
        .map(|(_, v)| *v)
        .ok_or_else(|| verify_err("no commitment versions"))?;

    for (_, version) in versions {
        if !is_similar_tap_commitment_version(
            Some(&first_version),
            Some(version),
        ) {
            return Err(verify_err("mixed anchor commitment versions"));
        }
    }

    Ok(Some(first_version))
}

// ---------------------------------------------------------------------
// Top-level verification (Go proof/verifier.go Verify/VerifyProofIntegrity)
// ---------------------------------------------------------------------

impl Proof {
    /// Verifies the integrity of the proof (steps 0 to 7 of the
    /// verification process), mirroring Go's
    /// `Proof.VerifyProofIntegrity` (proof/verifier.go:1063). Returns
    /// the anchored Taproot Asset commitment.
    pub fn verify_integrity<H, M, G, C, I>(
        &self,
        ctx: &VerifierCtx<H, M, G, C, I>,
        opts: &ProofVerificationOptions,
    ) -> Result<TapCommitment, ProofError>
    where
        H: HeaderVerifier,
        M: MerkleVerifier,
        G: GroupVerifier,
        C: ChainLookup,
        I: IgnoreChecker,
    {
        // 0. The proof version is checked during decoding (the
        // TransitionVersion enum has no unknown variant).

        // Ensure the proof asset is valid (Go's Asset.Validate only
        // checks the asset name).
        validate_asset_name(&self.asset.genesis.tag)?;

        // Before any other per-proof validation, check if this proof is
        // already known to be invalid via the optional ignore checker.
        // This is a rejection caching mechanism, mirroring Go's
        // `VerifyProofIntegrity` (proof/verifier.go:1088-1105): the
        // asset point produced by this proof (outpoint, asset ID,
        // script key) is checked against the set of ignored points.
        if let Some(checker) = &ctx.ignore_checker {
            let asset_point = PrevId {
                out_point: self.out_point(),
                id: self.asset.id(),
                script_key: *self.asset.script_key.serialized(),
            };
            if checker.is_ignored(&asset_point)? {
                return Err(ProofError::VerificationFailed(format!(
                    "invalid proof: asset point {:?} is ignored",
                    asset_point
                )));
            }
        }

        // 1. A transaction that spends the previous asset output has a
        // valid merkle proof within a block in the chain.
        if !tx_spends_prev_out(&self.anchor_tx.0, &self.prev_out) {
            return Err(verify_err(
                "invalid taproot proof: doesn't spend prev output",
            ));
        }

        if !opts.skip_chain_verification {
            // Cross-check the block header.
            ctx.header_verifier
                .verify_header(&self.block_header, self.block_height)?;

            // Assert that the transaction is in the block via the
            // merkle proof.
            ctx.merkle_verifier.verify_merkle_proof(
                &self.anchor_tx.txid(),
                &self.tx_merkle_proof,
                &self.block_header.merkle_root(),
            )?;
        }

        // 2.-4. Inclusion, split root, and exclusion proofs.
        let tap_commitment = self.verify_proofs()?;

        // 5. Genesis reveal checks (Go proof/verifier.go:1148-1166).
        let is_genesis_asset = self.asset.is_genesis_asset();
        let has_genesis_reveal = self.genesis_reveal.is_some();
        let has_meta_reveal = self.meta_reveal.is_some();

        match (is_genesis_asset, has_genesis_reveal, has_meta_reveal) {
            (false, true, _) => {
                return Err(verify_err(
                    "non genesis asset has genesis reveal",
                ))
            }
            (false, false, true) => {
                return Err(verify_err(
                    "non genesis asset has meta reveal",
                ))
            }
            (true, false, _) => {
                return Err(verify_err("genesis reveal required"))
            }
            (true, true, _) => self.verify_genesis_reveal()?,
            (false, false, false) => {}
        }

        // 6. Group key and group key reveal checks for genesis assets
        // (Go proof/verifier.go:1172-1193).
        let has_group_key_reveal = self.group_key_reveal.is_some();
        let has_group_key = self.asset.group_key.is_some();
        match (is_genesis_asset, has_group_key, has_group_key_reveal) {
            (false, _, true) => {
                return Err(verify_err(
                    "non genesis asset has group key reveal",
                ))
            }
            (true, false, true) => {
                return Err(verify_err("group key required"))
            }
            (true, true, false) => {
                // A reissuance must be for an asset group that has
                // already been imported and verified.
                self.verify_genesis_group_key(&ctx.group_verifier)?;
            }
            (true, true, true) => self.verify_group_key_reveal()?,
            _ => {}
        }

        // 7. Any transferred asset with a group key must carry a group
        // key that has already been imported and verified.
        if !is_genesis_asset && has_group_key {
            self.verify_genesis_group_key(&ctx.group_verifier)?;
        }

        Ok(tap_commitment)
    }

    /// Verifies that the asset's group key has already been verified by
    /// the external group verifier, mirroring Go's
    /// `Proof.verifyGenesisGroupKey` (proof/verifier.go:812).
    fn verify_genesis_group_key<G: GroupVerifier>(
        &self,
        group_verifier: &G,
    ) -> Result<(), ProofError> {
        let group_key = self
            .asset
            .group_key
            .as_ref()
            .ok_or_else(|| verify_err("group key required"))?;
        group_verifier
            .verify_group_key(&group_key.group_pub_key)
            .map_err(|e| verify_err(format!("group key not known: {}", e)))
    }

    /// Verifies an asset state transition, mirroring Go's
    /// `Proof.verifyAssetStateTransition` (proof/verifier.go:601).
    /// Returns true if this state transition represents an asset split.
    fn verify_asset_state_transition<H, M, G, C, I>(
        &self,
        prev: Option<&AssetSnapshot>,
        ctx: &VerifierCtx<H, M, G, C, I>,
        opts: &ProofVerificationOptions,
    ) -> Result<bool, ProofError>
    where
        H: HeaderVerifier,
        M: MerkleVerifier,
        G: GroupVerifier,
        C: ChainLookup,
        I: IgnoreChecker,
    {
        // Determine whether we have an asset split based on the
        // resulting asset's witness. If so, the VM runs on the root
        // asset extracted from the split commitment.
        let mut split_assets = Vec::new();
        let new_asset: Asset;
        if self.asset.has_split_commitment_witness() {
            split_assets.push(crate::commitment::SplitAsset {
                asset: self.asset.clone(),
                output_index: self.inclusion_proof.output_index,
            });
            new_asset = self.split_root_asset()?;
        } else {
            new_asset = self.asset.clone();
        }

        // Gather the set of asset inputs leading to the state
        // transition.
        let mut prev_assets: vm::InputSet = HashMap::new();
        if let Some(prev) = prev {
            prev_assets.insert(
                PrevId {
                    out_point: self.prev_out.clone(),
                    id: prev.asset.genesis.id(),
                    script_key: *prev.asset.script_key.serialized(),
                },
                prev.asset.clone(),
            );
        }

        // Verify all additional input proof files with the same
        // verifier context. Go uses default verification options here
        // (chain verification enabled).
        for input_file in &self.additional_inputs {
            let result = input_file
                .verify(ctx, &ProofVerificationOptions::default())
                .map_err(|e| {
                    verify_err(format!("inputs invalid: {}", e))
                })?;
            prev_assets.insert(
                PrevId {
                    out_point: result.out_point.clone(),
                    id: result.asset.genesis.id(),
                    script_key: *result.asset.script_key.serialized(),
                },
                result.asset,
            );
        }

        // Time lock validation (done in Go's VM via ChainLookup).
        if !opts.skip_time_lock_validation && asset_uses_time_lock(&new_asset)
        {
            check_time_locks(
                &new_asset,
                self.block_height,
                &ctx.chain_lookup,
            )?;
        }

        // Spawn a VM instance to verify the state transition.
        let validator = crate::crypto::SchnorrWitnessValidator::new();
        let engine = vm::Engine::new(
            &new_asset,
            &split_assets,
            &prev_assets,
            &validator,
        );
        engine
            .execute()
            .map_err(|e| verify_err(format!("state transition: {}", e)))?;

        Ok(!split_assets.is_empty())
    }

    /// Verifies the proof, mirroring Go's `Proof.Verify`
    /// (proof/verifier.go:993):
    ///
    /// 0. The proof has a valid version.
    /// 1. The anchor transaction spends the previous asset output and
    ///    has a valid merkle proof within a block in the chain.
    /// 2. A valid inclusion proof for the resulting asset is included.
    /// 3. A valid inclusion proof for the split root, if the resulting
    ///    asset is a split asset.
    /// 4. A set of valid exclusion proofs for the resulting asset is
    ///    included.
    /// 5.-7. Genesis reveal / group key reveal checks.
    /// 8. Either a set of asset inputs with valid witnesses satisfying
    ///    the state transition, or a valid ownership challenge witness.
    pub fn verify<H, M, G, C, I>(
        &self,
        prev: Option<&AssetSnapshot>,
        ctx: &VerifierCtx<H, M, G, C, I>,
        opts: &ProofVerificationOptions,
    ) -> Result<AssetSnapshot, ProofError>
    where
        H: HeaderVerifier,
        M: MerkleVerifier,
        G: GroupVerifier,
        C: ChainLookup,
        I: IgnoreChecker,
    {
        // Steps 0 to 7 (excluding step 1b that needs the previous asset
        // snapshot).
        let tap_commitment = self.verify_integrity(ctx, opts)?;

        // 1b. The anchor transaction spends the previous snapshot's
        // outpoint.
        if let Some(prev) = prev {
            if self.prev_out != prev.out_point {
                return Err(verify_err(
                    "invalid taproot proof: prev output mismatch",
                ));
            }
        }

        // 8. Either a valid state transition or a challenge witness.
        let split_asset = match (&prev, &self.challenge_witness) {
            (None, Some(_)) => super::ownership::verify_challenge_witness(
                self,
                opts.challenge_bytes,
            )?,
            _ => self.verify_asset_state_transition(prev, ctx, opts)?,
        };

        // The inclusion proof is known to be a commitment proof at this
        // point, so the tapscript sibling can be extracted directly.
        let tapscript_sibling = self
            .inclusion_proof
            .commitment_proof
            .as_ref()
            .and_then(|cp| cp.tap_sibling_preimage.clone());

        Ok(AssetSnapshot {
            asset: self.asset.clone(),
            out_point: self.out_point(),
            anchor_block_hash: self.block_header.block_hash(),
            anchor_block_height: self.block_height,
            anchor_tx: self.anchor_tx.clone(),
            output_index: self.inclusion_proof.output_index,
            internal_key: self.inclusion_proof.internal_key,
            script_root: Some(tap_commitment),
            tapscript_sibling,
            split_asset,
            meta_reveal: self.meta_reveal.clone(),
        })
    }
}

impl super::file::File {
    /// Verifies a full proof file starting from the asset's genesis,
    /// mirroring Go's `File.Verify` (proof/verifier.go:1352): proofs
    /// are verified sequentially, with each proof's `prev_out` required
    /// to spend the previous proof's outpoint. Returns the snapshot of
    /// the final state transition.
    pub fn verify<H, M, G, C, I>(
        &self,
        ctx: &VerifierCtx<H, M, G, C, I>,
        opts: &ProofVerificationOptions,
    ) -> Result<AssetSnapshot, ProofError>
    where
        H: HeaderVerifier,
        M: MerkleVerifier,
        G: GroupVerifier,
        C: ChainLookup,
        I: IgnoreChecker,
    {
        if self.version != super::file::FILE_VERSION_V0 {
            return Err(verify_err(format!(
                "unknown proof file version: {}",
                self.version
            )));
        }

        if self.proofs.is_empty() {
            return Err(ProofError::EmptyFile);
        }

        let mut prev: Option<AssetSnapshot> = None;
        for hashed in &self.proofs {
            let decoded = super::decode::decode_proof(&hashed.proof_bytes)?;
            let result = decoded.verify(prev.as_ref(), ctx, opts)?;
            prev = Some(result);
        }

        prev.ok_or(ProofError::EmptyFile)
    }
}

// ---------------------------------------------------------------------
// Structural checks (lighter, pre-existing API)
// ---------------------------------------------------------------------

/// Verifies a single transition proof.
///
/// This performs structural validation of the proof only; the full
/// pipeline is [`Proof::verify`].
pub fn verify_proof_structure(proof: &Proof) -> Result<(), ProofError> {
    // Step 0: Check version.
    match proof.version {
        TransitionVersion::V0 | TransitionVersion::V1 => {}
    }

    // Step 6: If genesis, verify the reveal.
    if proof.asset.is_genesis_asset() {
        if let Some(ref reveal) = proof.genesis_reveal {
            // The genesis reveal's ID must match the asset's genesis ID.
            if reveal.id() != proof.asset.genesis.id() {
                return Err(ProofError::GenesisMismatch);
            }

            // The genesis first_prev_out must match the proof's prev_out.
            if reveal.first_prev_out != proof.prev_out {
                return Err(ProofError::GenesisPrevOutMismatch);
            }

            // If meta reveal is present, verify the meta hash.
            if let Some(ref meta) = proof.meta_reveal {
                meta.validate()?;
                if meta.meta_hash() != reveal.meta_hash {
                    return Err(ProofError::MetaHashMismatch);
                }
            }
        }
    }

    Ok(())
}

/// Verifies the structural integrity of a proof file.
///
/// Checks that the hash chain is valid and proofs link correctly
/// (each proof's prev_out matches the previous proof's anchor outpoint).
pub fn verify_file_structure(
    file: &super::file::File,
) -> Result<(), ProofError> {
    if !file.verify_hash_chain() {
        return Err(ProofError::InvalidProofHash);
    }

    if file.proofs.is_empty() {
        return Err(ProofError::EmptyFile);
    }

    Ok(())
}

// ---------------------------------------------------------------------
// Default/test implementations
// ---------------------------------------------------------------------

/// A no-op header verifier (trusts all headers). Only available in tests
/// or when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
pub struct TrustAllHeaders;

#[cfg(any(test, feature = "test-utils"))]
impl HeaderVerifier for TrustAllHeaders {
    fn verify_header(
        &self,
        _header: &BlockHeader,
        _height: u32,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

/// A default Merkle verifier that uses `TxMerkleProof::verify`.
pub struct DefaultMerkleVerifier;

impl MerkleVerifier for DefaultMerkleVerifier {
    fn verify_merkle_proof(
        &self,
        tx_hash: &[u8; 32],
        proof: &super::tx_merkle::TxMerkleProof,
        merkle_root: &[u8; 32],
    ) -> Result<(), ProofError> {
        if proof.verify(tx_hash, merkle_root) {
            Ok(())
        } else {
            Err(ProofError::InvalidTxMerkleProof)
        }
    }
}

/// A no-op group verifier (trusts all group keys). Only available in tests
/// or when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
pub struct TrustAllGroups;

#[cfg(any(test, feature = "test-utils"))]
impl GroupVerifier for TrustAllGroups {
    fn verify_group_key(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;
    use crate::proof::tx_merkle::TxMerkleProof;

    fn dummy_proof() -> Proof {
        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let asset = Asset::new_genesis(
            genesis.clone(),
            100,
            ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        );

        Proof {
            version: TransitionVersion::V0,
            prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            block_header: BlockHeader::default(),
            block_height: 100,
            anchor_tx: AnchorTx::default(),
            tx_merkle_proof: TxMerkleProof {
                nodes: vec![],
                bits: vec![],
            },
            asset,
            inclusion_proof: TaprootProof {
                output_index: 0,
                internal_key: SerializedKey([0x02; 33]),
                commitment_proof: None,
                tapscript_proof: None,
                unknown_odd_types: std::collections::BTreeMap::new(),
            },
            exclusion_proofs: vec![],
            split_root_proof: None,
            meta_reveal: None,
            additional_inputs: vec![],
            challenge_witness: None,
            genesis_reveal: Some(genesis),
            group_key_reveal: None,
            alt_leaves: vec![],
            unknown_odd_types: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn test_verify_valid_genesis_proof() {
        let proof = dummy_proof();
        assert!(verify_proof_structure(&proof).is_ok());
    }

    #[test]
    fn test_verify_genesis_id_mismatch() {
        let mut proof = dummy_proof();
        // Tamper with the genesis reveal.
        if let Some(ref mut reveal) = proof.genesis_reveal {
            reveal.tag = "different-tag".to_string();
        }
        assert!(matches!(
            verify_proof_structure(&proof),
            Err(ProofError::GenesisMismatch)
        ));
    }

    #[test]
    fn test_verify_genesis_prev_out_mismatch() {
        let mut proof = dummy_proof();
        proof.prev_out = OutPoint {
            txid: [0xFF; 32],
            vout: 99,
        };
        assert!(matches!(
            verify_proof_structure(&proof),
            Err(ProofError::GenesisPrevOutMismatch)
        ));
    }

    /// An ignore checker that ignores a single asset point.
    struct SinglePointChecker(PrevId);

    impl IgnoreChecker for SinglePointChecker {
        fn is_ignored(&self, prev_id: &PrevId) -> Result<bool, ProofError> {
            Ok(*prev_id == self.0)
        }
    }

    /// A proof whose produced asset point is ignored fails verification
    /// immediately, mirroring Go's rejection cache in
    /// `VerifyProofIntegrity` (proof/verifier.go:1088-1105).
    #[test]
    fn test_ignored_asset_point_rejected() {
        let proof = dummy_proof();
        let asset_point = PrevId {
            out_point: proof.out_point(),
            id: proof.asset.id(),
            script_key: *proof.asset.script_key.serialized(),
        };

        let ctx = VerifierCtx::new(
            TrustAllHeaders,
            DefaultMerkleVerifier,
            TrustAllGroups,
            FixedHeightChainLookup(100),
        )
        .with_ignore_checker(SinglePointChecker(asset_point));

        let err = proof
            .verify_integrity(&ctx, &ProofVerificationOptions::default())
            .expect_err("ignored proof must fail");
        assert!(
            err.to_string().contains("is ignored"),
            "unexpected error: {}",
            err
        );

        // A checker that ignores a different point does not trigger on
        // this proof (verification proceeds and fails later for other
        // reasons).
        let other_point = PrevId {
            out_point: OutPoint {
                txid: [0xEE; 32],
                vout: 1,
            },
            id: proof.asset.id(),
            script_key: *proof.asset.script_key.serialized(),
        };
        let ctx = VerifierCtx::new(
            TrustAllHeaders,
            DefaultMerkleVerifier,
            TrustAllGroups,
            FixedHeightChainLookup(100),
        )
        .with_ignore_checker(SinglePointChecker(other_point));
        let err = proof
            .verify_integrity(&ctx, &ProofVerificationOptions::default())
            .expect_err("dummy proof still fails downstream");
        assert!(
            !err.to_string().contains("is ignored"),
            "unexpected ignore error: {}",
            err
        );
    }

    #[test]
    fn test_asset_name_go_print_semantics() {
        // Accepted: letters, numbers, punctuation, symbols (including
        // emoji, category So), and the ASCII space.
        for name in ["USD Coin", "asset-1_2.3", "emoji \u{1F600}", "caf\u{e9}"] {
            assert!(
                validate_asset_name(name).is_ok(),
                "expected {:?} to be accepted",
                name
            );
        }

        // Rejected like Go's !unicode.IsPrint: control, format (zero
        // width space, soft hyphen, zero width joiner), and non-ASCII
        // separators (no-break space, ideographic space).
        for name in [
            "bad\u{0007}name",
            "zero\u{200B}width",
            "soft\u{00AD}hyphen",
            "joiner\u{200D}x",
            "nbsp\u{00A0}x",
            "wide\u{3000}space",
            "tab\tname",
            "line\nname",
        ] {
            assert!(
                validate_asset_name(name).is_err(),
                "expected {:?} to be rejected",
                name
            );
        }
    }
}
