// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Core types for the Universe sync system.

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;

/// Identifies a specific universe (one tree per asset/proof-type pair).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UniverseId {
    /// The asset ID this universe tracks.
    pub asset_id: AssetId,
    /// Optional group key (for grouped assets).
    pub group_key: Option<SerializedKey>,
    /// The type of proofs stored in this universe.
    pub proof_type: ProofType,
}

/// What kind of proofs a universe stores.
///
/// Mirrors Go's `universe.ProofType` (universe/interface.go:820).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProofType {
    /// Only issuance (genesis) proofs.
    Issuance,
    /// All transfer proofs.
    Transfer,
    /// Signed ignore tuples (supply commitment ignore sub-tree).
    Ignore,
    /// Burn proofs (supply commitment burn sub-tree).
    Burn,
    /// Mint proofs within the supply commitment mint sub-tree.
    MintSupply,
}

impl ProofType {
    /// Returns the Go-compatible string representation
    /// (universe/interface.go `ProofType.String`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofType::Issuance => "issuance",
            ProofType::Transfer => "transfer",
            ProofType::Ignore => "ignore",
            ProofType::Burn => "burn",
            ProofType::MintSupply => "mint_supply",
        }
    }

    /// Parses the Go-compatible string representation
    /// (universe/interface.go `ParseStrProofType`).
    pub fn from_str_name(s: &str) -> Option<ProofType> {
        match s {
            "issuance" => Some(ProofType::Issuance),
            "transfer" => Some(ProofType::Transfer),
            "ignore" => Some(ProofType::Ignore),
            "burn" => Some(ProofType::Burn),
            "mint_supply" => Some(ProofType::MintSupply),
            _ => None,
        }
    }
}

/// The type of sync to perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncType {
    /// Sync only issuance proofs (asset discovery).
    IssuanceOnly,
    /// Full sync (issuance + transfers).
    Full,
}

/// A key identifying a leaf in a universe tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeafKey {
    /// The anchor outpoint of the proof.
    pub outpoint: OutPoint,
    /// The script key of the asset.
    pub script_key: SerializedKey,
}

/// A leaf in a universe tree.
#[derive(Clone, Debug)]
pub struct UniverseLeaf {
    /// The asset ID.
    pub asset_id: AssetId,
    /// The amount.
    pub amount: u64,
    /// Encoded proof data.
    pub proof: Vec<u8>,
    /// The leaf key.
    pub key: LeafKey,
}

/// A universe proof: a leaf plus its inclusion proof in the tree.
#[derive(Clone, Debug)]
pub struct UniverseProof {
    /// The leaf data.
    pub leaf: UniverseLeaf,
    /// MS-SMT inclusion proof (compressed).
    pub inclusion_proof: Vec<u8>,
}

/// The root of a universe tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniverseRoot {
    /// Which universe this root belongs to.
    pub id: UniverseId,
    /// The MS-SMT root hash.
    pub root_hash: NodeHash,
    /// The MS-SMT root sum.
    pub root_sum: u64,
}

/// A remote universe server address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServerAddr {
    /// The server's host:port.
    pub host: String,
    /// Unique identifier (derived from host if not set).
    pub id: String,
}

impl ServerAddr {
    pub fn new(host: String) -> Self {
        let id = host.clone();
        ServerAddr { host, id }
    }
}

/// A diff resulting from a sync operation.
#[derive(Clone, Debug)]
pub struct AssetSyncDiff {
    /// The universe that was synced.
    pub universe_id: UniverseId,
    /// New leaves added during sync.
    pub new_leaves: Vec<UniverseLeaf>,
}

/// Query parameters for listing leaf keys.
#[derive(Clone, Debug, Default)]
pub struct LeafKeysQuery {
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// Offset for pagination.
    pub offset: Option<u32>,
}

/// Query parameters for listing root nodes.
#[derive(Clone, Debug, Default)]
pub struct RootNodesQuery {
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// Offset for pagination.
    pub offset: Option<u32>,
}

/// Errors from universe operations.
#[derive(Debug, Clone)]
pub enum UniverseError {
    /// The requested universe does not exist.
    NotFound(String),
    /// Tree operation failed.
    TreeError(String),
    /// Proof validation failed.
    ProofInvalid(String),
    /// Remote sync failed.
    SyncError(String),
    /// Storage error.
    StoreError(String),
}

impl std::fmt::Display for UniverseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UniverseError::NotFound(msg) => {
                write!(f, "universe not found: {}", msg)
            }
            UniverseError::TreeError(msg) => {
                write!(f, "tree error: {}", msg)
            }
            UniverseError::ProofInvalid(msg) => {
                write!(f, "proof invalid: {}", msg)
            }
            UniverseError::SyncError(msg) => {
                write!(f, "sync error: {}", msg)
            }
            UniverseError::StoreError(msg) => {
                write!(f, "store error: {}", msg)
            }
        }
    }
}

impl std::error::Error for UniverseError {}

// ---------------------------------------------------------------------------
// Serde support (feature = "serde")
// ---------------------------------------------------------------------------

/// JSON-friendly (de)serialization for the universe wire types, so a
/// server crate can expose them over REST/loopback APIs. Byte fields
/// are hex-encoded strings; txids use internal byte order.
///
/// Implemented via DTO structs because the inner tap-primitives types
/// (`AssetId`, `SerializedKey`, `NodeHash`, `OutPoint`) are foreign and
/// cannot receive serde impls here (orphan rule).
#[cfg(feature = "serde")]
mod serde_impls {
    use super::*;
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn from_hex(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex: {}", e))
            })
            .collect()
    }

    fn from_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
        let bytes = from_hex(s)?;
        let mut out = [0u8; N];
        if bytes.len() != N {
            return Err(format!(
                "expected {} bytes, got {}",
                N,
                bytes.len()
            ));
        }
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    macro_rules! dto_serde {
        ($ty:ty, $dto:ty) => {
            impl Serialize for $ty {
                fn serialize<S: Serializer>(
                    &self,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    <$dto>::from(self).serialize(serializer)
                }
            }

            impl<'de> Deserialize<'de> for $ty {
                fn deserialize<D: Deserializer<'de>>(
                    deserializer: D,
                ) -> Result<Self, D::Error> {
                    let dto = <$dto>::deserialize(deserializer)?;
                    dto.try_into().map_err(D::Error::custom)
                }
            }
        };
    }

    // --- ProofType ---

    impl Serialize for ProofType {
        fn serialize<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(self.as_str())
        }
    }

    impl<'de> Deserialize<'de> for ProofType {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            let s = String::deserialize(deserializer)?;
            ProofType::from_str_name(&s).ok_or_else(|| {
                D::Error::custom(format!("unknown proof type {:?}", s))
            })
        }
    }

    // --- UniverseId ---

    #[derive(Serialize, Deserialize)]
    struct UniverseIdDto {
        asset_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_key: Option<String>,
        proof_type: ProofType,
    }

    impl From<&UniverseId> for UniverseIdDto {
        fn from(id: &UniverseId) -> Self {
            UniverseIdDto {
                asset_id: to_hex(id.asset_id.as_bytes()),
                group_key: id
                    .group_key
                    .as_ref()
                    .map(|k| to_hex(k.as_bytes())),
                proof_type: id.proof_type,
            }
        }
    }

    impl TryFrom<UniverseIdDto> for UniverseId {
        type Error = String;

        fn try_from(dto: UniverseIdDto) -> Result<Self, String> {
            Ok(UniverseId {
                asset_id: AssetId(from_hex_array(&dto.asset_id)?),
                group_key: dto
                    .group_key
                    .as_deref()
                    .map(|s| Ok(SerializedKey(from_hex_array(s)?)))
                    .transpose()
                    .map_err(|e: String| e)?,
                proof_type: dto.proof_type,
            })
        }
    }

    dto_serde!(UniverseId, UniverseIdDto);

    // --- LeafKey ---

    #[derive(Serialize, Deserialize)]
    struct LeafKeyDto {
        /// Anchor txid, hex, internal byte order.
        txid: String,
        vout: u32,
        script_key: String,
    }

    impl From<&LeafKey> for LeafKeyDto {
        fn from(key: &LeafKey) -> Self {
            LeafKeyDto {
                txid: to_hex(&key.outpoint.txid),
                vout: key.outpoint.vout,
                script_key: to_hex(key.script_key.as_bytes()),
            }
        }
    }

    impl TryFrom<LeafKeyDto> for LeafKey {
        type Error = String;

        fn try_from(dto: LeafKeyDto) -> Result<Self, String> {
            Ok(LeafKey {
                outpoint: OutPoint {
                    txid: from_hex_array(&dto.txid)?,
                    vout: dto.vout,
                },
                script_key: SerializedKey(from_hex_array(
                    &dto.script_key,
                )?),
            })
        }
    }

    dto_serde!(LeafKey, LeafKeyDto);

    // --- UniverseLeaf ---

    #[derive(Serialize, Deserialize)]
    struct UniverseLeafDto {
        asset_id: String,
        amount: u64,
        /// Raw proof, hex.
        proof: String,
        key: LeafKey,
    }

    impl From<&UniverseLeaf> for UniverseLeafDto {
        fn from(leaf: &UniverseLeaf) -> Self {
            UniverseLeafDto {
                asset_id: to_hex(leaf.asset_id.as_bytes()),
                amount: leaf.amount,
                proof: to_hex(&leaf.proof),
                key: leaf.key.clone(),
            }
        }
    }

    impl TryFrom<UniverseLeafDto> for UniverseLeaf {
        type Error = String;

        fn try_from(dto: UniverseLeafDto) -> Result<Self, String> {
            Ok(UniverseLeaf {
                asset_id: AssetId(from_hex_array(&dto.asset_id)?),
                amount: dto.amount,
                proof: from_hex(&dto.proof)?,
                key: dto.key,
            })
        }
    }

    dto_serde!(UniverseLeaf, UniverseLeafDto);

    // --- UniverseProof ---

    #[derive(Serialize, Deserialize)]
    struct UniverseProofDto {
        leaf: UniverseLeaf,
        /// Compressed MS-SMT inclusion proof, hex.
        inclusion_proof: String,
    }

    impl From<&UniverseProof> for UniverseProofDto {
        fn from(proof: &UniverseProof) -> Self {
            UniverseProofDto {
                leaf: proof.leaf.clone(),
                inclusion_proof: to_hex(&proof.inclusion_proof),
            }
        }
    }

    impl TryFrom<UniverseProofDto> for UniverseProof {
        type Error = String;

        fn try_from(dto: UniverseProofDto) -> Result<Self, String> {
            Ok(UniverseProof {
                leaf: dto.leaf,
                inclusion_proof: from_hex(&dto.inclusion_proof)?,
            })
        }
    }

    dto_serde!(UniverseProof, UniverseProofDto);

    // --- UniverseRoot ---

    #[derive(Serialize, Deserialize)]
    struct UniverseRootDto {
        id: UniverseId,
        root_hash: String,
        root_sum: u64,
    }

    impl From<&UniverseRoot> for UniverseRootDto {
        fn from(root: &UniverseRoot) -> Self {
            UniverseRootDto {
                id: root.id.clone(),
                root_hash: to_hex(&root.root_hash.0),
                root_sum: root.root_sum,
            }
        }
    }

    impl TryFrom<UniverseRootDto> for UniverseRoot {
        type Error = String;

        fn try_from(dto: UniverseRootDto) -> Result<Self, String> {
            Ok(UniverseRoot {
                id: dto.id,
                root_hash: NodeHash(from_hex_array(&dto.root_hash)?),
                root_sum: dto.root_sum,
            })
        }
    }

    dto_serde!(UniverseRoot, UniverseRootDto);

    // --- AssetSyncDiff ---

    #[derive(Serialize, Deserialize)]
    struct AssetSyncDiffDto {
        universe_id: UniverseId,
        new_leaves: Vec<UniverseLeaf>,
    }

    impl From<&AssetSyncDiff> for AssetSyncDiffDto {
        fn from(diff: &AssetSyncDiff) -> Self {
            AssetSyncDiffDto {
                universe_id: diff.universe_id.clone(),
                new_leaves: diff.new_leaves.clone(),
            }
        }
    }

    impl TryFrom<AssetSyncDiffDto> for AssetSyncDiff {
        type Error = String;

        fn try_from(dto: AssetSyncDiffDto) -> Result<Self, String> {
            Ok(AssetSyncDiff {
                universe_id: dto.universe_id,
                new_leaves: dto.new_leaves,
            })
        }
    }

    dto_serde!(AssetSyncDiff, AssetSyncDiffDto);

    // --- ServerAddr ---

    #[derive(Serialize, Deserialize)]
    struct ServerAddrDto {
        host: String,
        id: String,
    }

    impl From<&ServerAddr> for ServerAddrDto {
        fn from(addr: &ServerAddr) -> Self {
            ServerAddrDto {
                host: addr.host.clone(),
                id: addr.id.clone(),
            }
        }
    }

    impl TryFrom<ServerAddrDto> for ServerAddr {
        type Error = String;

        fn try_from(dto: ServerAddrDto) -> Result<Self, String> {
            Ok(ServerAddr {
                host: dto.host,
                id: dto.id,
            })
        }
    }

    dto_serde!(ServerAddr, ServerAddrDto);

    #[cfg(test)]
    mod tests {
        use super::*;

        fn roundtrip<T>(value: &T) -> T
        where
            T: Serialize + for<'de> Deserialize<'de>,
        {
            let json = serde_json::to_string(value).expect("serialize");
            serde_json::from_str(&json).expect("deserialize")
        }

        #[test]
        fn test_serde_roundtrips() {
            let id = UniverseId {
                asset_id: AssetId([0x11; 32]),
                group_key: Some(SerializedKey([0x02; 33])),
                proof_type: ProofType::Transfer,
            };
            let back = roundtrip(&id);
            assert_eq!(back, id);

            let key = LeafKey {
                outpoint: OutPoint {
                    txid: [0xAB; 32],
                    vout: 5,
                },
                script_key: SerializedKey([0x03; 33]),
            };
            assert_eq!(roundtrip(&key), key);

            let leaf = UniverseLeaf {
                asset_id: AssetId([0x11; 32]),
                amount: 42,
                proof: vec![0xDE, 0xAD],
                key: key.clone(),
            };
            let leaf_back = roundtrip(&leaf);
            assert_eq!(leaf_back.asset_id, leaf.asset_id);
            assert_eq!(leaf_back.amount, leaf.amount);
            assert_eq!(leaf_back.proof, leaf.proof);
            assert_eq!(leaf_back.key, leaf.key);

            let proof = UniverseProof {
                leaf,
                inclusion_proof: vec![0x01, 0x02],
            };
            let proof_back = roundtrip(&proof);
            assert_eq!(
                proof_back.inclusion_proof,
                proof.inclusion_proof
            );

            let root = UniverseRoot {
                id: id.clone(),
                root_hash: NodeHash([0x77; 32]),
                root_sum: 1000,
            };
            assert_eq!(roundtrip(&root), root);

            let addr = ServerAddr::new("universe.example.com:10029".into());
            assert_eq!(roundtrip(&addr), addr);
        }

        #[test]
        fn test_serde_rejects_bad_hex() {
            let bad = r#"{"asset_id":"zz","proof_type":"issuance"}"#;
            assert!(serde_json::from_str::<UniverseId>(bad).is_err());
        }
    }
}
