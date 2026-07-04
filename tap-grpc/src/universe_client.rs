// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Blocking gRPC client for `tapd`'s `universerpc.Universe` service.
//!
//! [`GrpcUniverseClient`] is the gRPC sibling of
//! [`tap_universe::HttpUniverseClient`]: it implements
//! [`DiffEngine`] (so it plugs into `SimpleSyncer` / `sync_all`) plus
//! the same `insert_proof` / `query_proof` surface, but speaks tapd's
//! NATIVE federation protocol (tapd itself syncs over gRPC, not
//! REST).
//!
//! Blocking design: the client owns a small private tokio runtime (or
//! borrows a [`tokio::runtime::Handle`]) and drives each unary RPC
//! with `block_on`. It must not be called from inside an async
//! context; use `tokio::task::spawn_blocking` there.

use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_universe::traits::DiffEngine;
use tap_universe::types::{
    LeafKey, LeafKeysQuery, ProofType, RootNodesQuery, UniverseError,
    UniverseId, UniverseLeaf, UniverseProof, UniverseRoot,
};

use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status};

use crate::blocking::BlockingRuntime;
use crate::convert;
use crate::universerpc;
use crate::universerpc::universe_client::UniverseClient;

/// Page size used when transparently paginating list RPCs, matching
/// Go's `universe.RequestPageSize`.
const PAGE_SIZE: u32 = 512;

/// The error message tapd returns when a queried proof does not exist
/// (`universe.ErrNoUniverseProofFound`, surfaced with gRPC code
/// `Unknown`).
const NO_PROOF_MSG: &str = "no universe proof found";

/// The error message tapd returns when a queried universe root does
/// not exist (`universe.ErrNoUniverseRoot`).
const NO_ROOT_MSG: &str = "no universe root found";

/// Transport security and authentication options for connecting to a
/// universe server.
///
/// A stock tapd serves its gRPC interface over TLS with a self-signed
/// certificate (`tls.cert` in its data dir) and authenticates calls
/// with a macaroon sent in the `macaroon` metadata header (hex
/// encoded), exactly like lnd. The default options (plaintext, no
/// macaroon) match rust-tap's own `tap-server` on a loopback
/// interface.
#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    /// PEM contents of the server's TLS certificate (tapd's
    /// `tls.cert`). The connection trusts exactly this certificate
    /// (byte-for-byte pinning; see [`crate::tls`] for why standard
    /// webpki validation cannot accept lnd-style self-signed certs).
    /// `None` connects in plaintext.
    pub tls_cert_pem: Option<Vec<u8>>,
    /// Overrides the TLS server name (SNI) sent in the handshake;
    /// defaults to the URI host. Certificate pinning does not check
    /// names, so this is rarely needed.
    pub tls_domain: Option<String>,
    /// Hex-encoded macaroon sent as the `macaroon` metadata header on
    /// every RPC (e.g. the contents of tapd's `admin.macaroon`, hex
    /// encoded). `None` sends no macaroon; tapd then only accepts
    /// calls that are macaroon-whitelisted (e.g. public universe
    /// queries when running with `--universe.public-access`).
    pub macaroon_hex: Option<String>,
}

/// A tonic [`Interceptor`] that attaches the `macaroon` metadata
/// header tapd (and lnd) use for authentication.
#[derive(Clone)]
pub struct MacaroonInterceptor {
    macaroon: Option<MetadataValue<Ascii>>,
}

impl MacaroonInterceptor {
    fn new(macaroon_hex: Option<&str>) -> Result<Self, UniverseError> {
        let macaroon = match macaroon_hex {
            Some(hex) => Some(hex.parse().map_err(|e| {
                sync_err("invalid macaroon hex for metadata", e)
            })?),
            None => None,
        };
        Ok(MacaroonInterceptor { macaroon })
    }
}

impl Interceptor for MacaroonInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, Status> {
        if let Some(macaroon) = &self.macaroon {
            request.metadata_mut().insert("macaroon", macaroon.clone());
        }
        Ok(request)
    }
}

/// The transport type of [`GrpcUniverseClient`]: a (possibly TLS)
/// channel with the macaroon interceptor applied.
type UniverseChannel = InterceptedService<Channel, MacaroonInterceptor>;

/// Blocking gRPC client for a tapd (or rust-tap `tap-server`)
/// universe server.
#[derive(Clone)]
pub struct GrpcUniverseClient {
    rt: BlockingRuntime,
    client: UniverseClient<UniverseChannel>,
}

fn sync_err(what: &str, e: impl std::fmt::Display) -> UniverseError {
    UniverseError::SyncError(format!("{}: {}", what, e))
}

impl GrpcUniverseClient {
    /// Connects to a universe gRPC server in plaintext without
    /// authentication, e.g. `http://127.0.0.1:10029` for a loopback
    /// `tap-server`. Creates a private single-worker tokio runtime for
    /// this client. For a real tapd (TLS + macaroon), use
    /// [`GrpcUniverseClient::connect_with_options`].
    pub fn connect(uri: &str) -> Result<Self, UniverseError> {
        Self::connect_with_options(uri, ConnectOptions::default())
    }

    /// Connects to a universe gRPC server with explicit transport
    /// options (TLS trust root, macaroon). Use
    /// `https://127.0.0.1:10029` style URIs when TLS is configured.
    pub fn connect_with_options(
        uri: &str,
        options: ConnectOptions,
    ) -> Result<Self, UniverseError> {
        let rt = BlockingRuntime::new_owned()
            .map_err(|e| sync_err("create runtime", e))?;
        Self::connect_inner(rt, uri, options)
    }

    /// Connects using an existing tokio runtime handle instead of
    /// owning one. The runtime must outlive the client, and the client
    /// must not be invoked from that runtime's async context (use
    /// `spawn_blocking`).
    pub fn connect_with_handle(
        handle: tokio::runtime::Handle,
        uri: &str,
    ) -> Result<Self, UniverseError> {
        Self::connect_inner(
            BlockingRuntime::from_handle(handle),
            uri,
            ConnectOptions::default(),
        )
    }

    /// [`GrpcUniverseClient::connect_with_handle`] with explicit
    /// transport options.
    pub fn connect_with_handle_options(
        handle: tokio::runtime::Handle,
        uri: &str,
        options: ConnectOptions,
    ) -> Result<Self, UniverseError> {
        Self::connect_inner(BlockingRuntime::from_handle(handle), uri, options)
    }

    fn connect_inner(
        rt: BlockingRuntime,
        uri: &str,
        options: ConnectOptions,
    ) -> Result<Self, UniverseError> {
        let endpoint = Endpoint::from_shared(uri.to_string())
            .map_err(|e| sync_err("invalid universe server uri", e))?;

        // tonic's transport error Display is just "transport error";
        // include the debug form so TLS failures are diagnosable.
        let channel = match &options.tls_cert_pem {
            Some(pem) => {
                let connector = crate::tls::pinned_tls_connector(
                    pem,
                    options.tls_domain.clone(),
                )
                .map_err(|e| sync_err("tls config", e))?;
                rt.block_on(endpoint.connect_with_connector(connector))
            }
            None => rt.block_on(endpoint.connect()),
        }
        .map_err(|e| {
            sync_err("connect universe server", format!("{:?}", e))
        })?;
        let interceptor =
            MacaroonInterceptor::new(options.macaroon_hex.as_deref())?;
        Ok(GrpcUniverseClient {
            rt,
            client: UniverseClient::with_interceptor(channel, interceptor),
        })
    }

    /// Registers a proof with the universe server via `InsertProof`,
    /// making the asset discoverable by peers. Mirrors
    /// `HttpUniverseClient::insert_proof`.
    pub fn insert_proof(
        &self,
        asset_id: &AssetId,
        proof_type: ProofType,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
        raw_proof_bytes: &[u8],
    ) -> Result<(), UniverseError> {
        let id = UniverseId {
            asset_id: *asset_id,
            group_key: None,
            proof_type,
        };
        let key = LeafKey {
            outpoint: *outpoint,
            script_key: *script_key,
        };
        let request = universerpc::AssetProof {
            key: Some(universerpc::UniverseKey {
                id: Some(convert::universe_id_to_proto(&id)?),
                leaf_key: Some(convert::leaf_key_to_proto(&key)),
            }),
            // The server sparse-decodes the asset from the proof
            // itself (Go unmarshalAssetLeaf); no Asset message needed.
            asset_leaf: Some(universerpc::AssetLeaf {
                asset: None,
                proof: raw_proof_bytes.to_vec(),
            }),
        };

        let mut client = self.client.clone();
        self.rt
            .block_on(client.insert_proof(request))
            .map_err(|e| sync_err("insert_proof", e))?;
        Ok(())
    }

    /// Queries a proof from the universe server. Returns the raw proof
    /// bytes, or `None` if the proof does not exist on the server.
    /// Mirrors `HttpUniverseClient::query_proof`.
    pub fn query_proof(
        &self,
        asset_id: &AssetId,
        proof_type: ProofType,
        outpoint: &OutPoint,
        script_key: &SerializedKey,
    ) -> Result<Option<Vec<u8>>, UniverseError> {
        let id = UniverseId {
            asset_id: *asset_id,
            group_key: None,
            proof_type,
        };
        let key = LeafKey {
            outpoint: *outpoint,
            script_key: *script_key,
        };
        Ok(self
            .fetch_proof_leaf(&id, &key)?
            .map(|proof| proof.leaf.proof))
    }

    /// Returns the server's pseudo-random runtime ID (`Info` RPC),
    /// useful as a reachability check and to detect duplicate servers.
    pub fn info(&self) -> Result<i64, UniverseError> {
        let mut client = self.client.clone();
        let response = self
            .rt
            .block_on(client.info(universerpc::InfoRequest {}))
            .map_err(|e| sync_err("info", e))?;
        Ok(response.into_inner().runtime_id)
    }

    /// True if the status signals "the proof does not exist" rather
    /// than a transport/server failure.
    fn is_no_proof(status: &Status) -> bool {
        status.code() == Code::NotFound
            || status.message().contains(NO_PROOF_MSG)
    }

    /// True if the status signals "the universe root does not exist".
    fn is_no_root(status: &Status) -> bool {
        status.code() == Code::NotFound
            || status.message().contains(NO_ROOT_MSG)
    }
}

impl DiffEngine for GrpcUniverseClient {
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError> {
        let request = universerpc::AssetRootQuery {
            id: Some(convert::universe_id_to_proto(id)?),
        };

        let mut client = self.client.clone();
        let response =
            match self.rt.block_on(client.query_asset_roots(request)) {
                Ok(response) => response.into_inner(),
                Err(status) if Self::is_no_root(&status) => {
                    return Err(UniverseError::NotFound(format!(
                        "no universe root for {:?}",
                        id
                    )))
                }
                Err(status) => {
                    return Err(sync_err("query_asset_roots", status))
                }
            };

        let root = match id.proof_type {
            ProofType::Issuance => response.issuance_root.as_ref(),
            ProofType::Transfer => response.transfer_root.as_ref(),
            other => {
                return Err(UniverseError::SyncError(format!(
                    "proof type {} not supported over universe RPC",
                    other.as_str()
                )))
            }
        };

        // tapd marshals an absent root as an empty message.
        match root {
            Some(root) if !convert::is_empty_universe_root(Some(root)) => {
                // Trust the requested id: the response echoes it (and
                // group-key responses omit the asset ID).
                let (root_hash, root_sum) =
                    convert::merkle_sum_node_from_proto(
                        root.mssmt_root.as_ref().ok_or_else(|| {
                            UniverseError::NotFound(format!(
                                "no universe root for {:?}",
                                id
                            ))
                        })?,
                    )?;
                Ok(UniverseRoot {
                    id: id.clone(),
                    root_hash,
                    root_sum,
                })
            }
            _ => Err(UniverseError::NotFound(format!(
                "no universe root for {:?}",
                id
            ))),
        }
    }

    fn root_nodes(
        &self,
        query: &RootNodesQuery,
    ) -> Result<Vec<UniverseRoot>, UniverseError> {
        // When the caller specifies an explicit page, issue a single
        // request; otherwise transparently walk all pages.
        let mut offset = query.offset.unwrap_or(0);
        let single_page = query.limit.is_some();
        let limit = query.limit.unwrap_or(PAGE_SIZE);

        let mut all_roots = Vec::new();
        loop {
            let request = universerpc::AssetRootRequest {
                with_amounts_by_id: false,
                offset: i32::try_from(offset).unwrap_or(i32::MAX),
                limit: i32::try_from(limit).unwrap_or(i32::MAX),
                direction: 0,
            };

            let mut client = self.client.clone();
            let response = self
                .rt
                .block_on(client.asset_roots(request))
                .map_err(|e| sync_err("asset_roots", e))?
                .into_inner();

            let page_len = response.universe_roots.len() as u32;
            for (map_key, root) in &response.universe_roots {
                // Skip roots we cannot represent (e.g. unspecified
                // proof type from future servers), but fail loudly on
                // malformed entries.
                match convert::universe_root_from_proto(root) {
                    Ok(root) => all_roots.push(root),
                    Err(_)
                        if root
                            .id
                            .as_ref()
                            .map(|id| {
                                convert::proof_type_from_proto(
                                    id.proof_type,
                                )
                                .is_err()
                            })
                            .unwrap_or(false) => {}
                    Err(e) => {
                        return Err(UniverseError::SyncError(format!(
                            "universe_roots[{}]: {}",
                            map_key, e
                        )))
                    }
                }
            }

            if single_page || !response.has_more || page_len == 0 {
                break;
            }
            offset += page_len;
        }

        Ok(all_roots)
    }

    fn universe_leaf_keys(
        &self,
        id: &UniverseId,
        query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError> {
        let proto_id = convert::universe_id_to_proto(id)?;
        let mut offset = query.offset.unwrap_or(0);
        let single_page = query.limit.is_some();
        let limit = query.limit.unwrap_or(PAGE_SIZE);

        let mut all_keys = Vec::new();
        loop {
            let request = universerpc::AssetLeafKeysRequest {
                id: Some(proto_id.clone()),
                offset: i32::try_from(offset).unwrap_or(i32::MAX),
                limit: i32::try_from(limit).unwrap_or(i32::MAX),
                direction: 0,
            };

            let mut client = self.client.clone();
            let response = self
                .rt
                .block_on(client.asset_leaf_keys(request))
                .map_err(|e| sync_err("asset_leaf_keys", e))?
                .into_inner();

            let page_len = response.asset_keys.len() as u32;
            for key in &response.asset_keys {
                all_keys.push(convert::leaf_key_from_proto(key)?);
            }

            if single_page || page_len == 0 {
                break;
            }
            // Servers that predate has_more signal the end with a
            // short page.
            if !response.has_more && page_len < limit {
                break;
            }
            offset += page_len;
        }

        Ok(all_keys)
    }

    fn fetch_proof_leaf(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError> {
        let request = universerpc::UniverseKey {
            id: Some(convert::universe_id_to_proto(id)?),
            leaf_key: Some(convert::leaf_key_to_proto(key)),
        };

        let mut client = self.client.clone();
        let response = match self.rt.block_on(client.query_proof(request)) {
            Ok(response) => response.into_inner(),
            Err(status) if Self::is_no_proof(&status) => return Ok(None),
            Err(status) => return Err(sync_err("query_proof", status)),
        };

        let asset_leaf = match response.asset_leaf {
            Some(leaf) if !leaf.proof.is_empty() => leaf,
            // A response without a proof payload means the leaf does
            // not exist.
            _ => return Ok(None),
        };

        // Prefer the amount reported by the server; fall back to
        // decoding the proof itself.
        let amount = match asset_leaf.asset.as_ref().map(|a| a.amount) {
            Some(amount) if amount > 0 => amount,
            _ => {
                tap_primitives::proof::decode_proof(&asset_leaf.proof)
                    .map_err(|e| {
                        UniverseError::ProofInvalid(format!(
                            "fetched proof does not decode: {}",
                            e
                        ))
                    })?
                    .asset
                    .amount
            }
        };

        Ok(Some(UniverseProof {
            leaf: UniverseLeaf {
                asset_id: id.asset_id,
                amount,
                proof: asset_leaf.proof,
                key: key.clone(),
            },
            inclusion_proof: response.universe_inclusion_proof,
        }))
    }
}
