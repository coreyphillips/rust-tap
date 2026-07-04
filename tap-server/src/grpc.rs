// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! gRPC (tonic) layer for the universe server: tapd-native federation.
//!
//! Serves the `universerpc.Universe` subset a peer needs to sync FROM
//! this server (tapd's own federation speaks gRPC, not REST):
//!
//! - `AssetRoots`, `QueryAssetRoots`: root discovery/diffing
//! - `AssetLeafKeys`, `AssetLeaves`: leaf enumeration
//! - `QueryProof`: proof fetch (the sync unit)
//! - `InsertProof`: validated proof push
//! - `Info`: reachability probe
//!
//! Everything else answers `Unimplemented`; the explicit list is
//! `MultiverseRoot` (rust-tap backends do not maintain a multiverse
//! tree), `DeleteAssetRoot`, `DeleteAssetLeaf`, `PushProof`,
//! `SyncUniverse`, the federation server management RPCs
//! (`ListFederationServers`, `AddFederationServer`,
//! `DeleteFederationServer`), the statistics RPCs (`UniverseStats`,
//! `QueryAssetStats`, `QueryEvents`), the federation sync config RPCs
//! (`SetFederationSyncConfig`, `QueryFederationSyncConfig`), and the
//! supply-commitment RPCs (`IgnoreAssetOutPoint`,
//! `UpdateSupplyCommit`, `FetchSupplyCommit`, `FetchSupplyLeaves`,
//! `InsertSupplyCommit`).
//!
//! The layer is marshaling only: every RPC delegates to the shared
//! transport-agnostic [`UniverseService`] (the same one behind the
//! REST router) via `spawn_blocking`, and all proto conversions come
//! from [`tap_grpc::convert`].
//!
//! Interop caveat: `AssetProofResponse.universe_inclusion_proof` is
//! whatever the backend stores. `MemoryUniverseBackend` keeps no real
//! MS-SMT inclusion proofs (empty bytes); a tapd client validates
//! that field, so full tapd-pull interop needs a backend that
//! produces real compressed MS-SMT proofs. rust-tap's own
//! `GrpcUniverseClient` + `SimpleSyncer` verify the raw proof itself
//! and sync fine either way.

use std::net::SocketAddr;

use tap_grpc::convert;
use tap_grpc::tonic::transport::server::Router;
use tap_grpc::tonic::transport::Server;
use tap_grpc::tonic::{Request, Response, Status};
use tap_grpc::universerpc::universe_server::{Universe, UniverseServer};
use tap_grpc::{taprpc, universerpc};

use tap_universe::types::{
    LeafKey, ProofType, UniverseError, UniverseLeaf, UniverseRoot,
};

use crate::service::{UniverseSelector, UniverseService};

/// Default page size when a request passes limit = 0, matching Go's
/// `universe.RequestPageSize`.
const DEFAULT_PAGE_SIZE: u32 = 512;

/// Maximum page size, matching Go's `universe.MaxPageSize`.
const MAX_PAGE_SIZE: u32 = 512;

/// The error message tapd emits for a missing proof
/// (`universe.ErrNoUniverseProofFound`); mirrored so gRPC clients can
/// map the miss.
const NO_PROOF_MSG: &str = "no universe proof found";

/// tonic service wrapper around the shared [`UniverseService`].
#[derive(Clone)]
pub struct GrpcUniverseService {
    service: UniverseService,
}

impl GrpcUniverseService {
    /// Wraps the shared universe service.
    pub fn new(service: UniverseService) -> Self {
        GrpcUniverseService { service }
    }

    /// Returns the ready-to-mount tonic server for this service.
    pub fn into_server(self) -> UniverseServer<GrpcUniverseService> {
        UniverseServer::new(self)
    }

    /// Runs a blocking service call on the blocking pool.
    async fn run_blocking<T, F>(&self, f: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(UniverseService) -> Result<T, UniverseError>
            + Send
            + 'static,
    {
        let service = self.service.clone();
        tokio::task::spawn_blocking(move || f(service))
            .await
            .map_err(|e| Status::internal(format!("join error: {}", e)))?
            .map_err(status_from_universe_error)
    }
}

/// Maps a [`UniverseError`] onto a gRPC status.
fn status_from_universe_error(e: UniverseError) -> Status {
    match e {
        UniverseError::NotFound(msg) => Status::not_found(msg),
        UniverseError::ProofInvalid(msg) => Status::invalid_argument(msg),
        other => Status::internal(other.to_string()),
    }
}

/// Validates offset/limit (Go `validatePage`) and applies the default
/// page size for limit = 0.
fn validate_page(offset: i32, limit: i32) -> Result<(u32, u32), Status> {
    if offset < 0 {
        return Err(Status::invalid_argument(format!(
            "invalid request offset: {}",
            offset
        )));
    }
    if limit < 0 || limit as u32 > MAX_PAGE_SIZE {
        return Err(Status::invalid_argument(format!(
            "invalid request limit: {}",
            limit
        )));
    }
    let limit = if limit == 0 {
        DEFAULT_PAGE_SIZE
    } else {
        limit as u32
    };
    Ok((offset as u32, limit))
}

/// Extracts the universe selector (asset ID or group key) from an RPC
/// `ID`, accepting all four oneof forms like Go's `UnmarshalUniID`.
fn selector_from_proto(
    id: &universerpc::Id,
) -> Result<UniverseSelector, Status> {
    use universerpc::id::Id as ProtoId;

    // Reuse the shared conversion for validation and normalization.
    let parsed = convert::universe_id_from_proto_parts(
        id,
        // The proof type is resolved separately by each RPC; issuance
        // is a placeholder for selector extraction only.
        ProofType::Issuance,
    )
    .map_err(|e| Status::invalid_argument(e.to_string()))?;

    match id.id.as_ref() {
        Some(ProtoId::AssetId(_)) | Some(ProtoId::AssetIdStr(_)) => {
            Ok(UniverseSelector::Asset(parsed.asset_id))
        }
        Some(ProtoId::GroupKey(_)) | Some(ProtoId::GroupKeyStr(_)) => {
            let gk = parsed.group_key.ok_or_else(|| {
                Status::invalid_argument("group key missing")
            })?;
            Ok(UniverseSelector::Group(gk.as_bytes().to_vec()))
        }
        None => Err(Status::invalid_argument(
            "id must set one of asset_id or group_key",
        )),
    }
}

/// Extracts the required proof type from an RPC `ID`.
fn required_proof_type(id: &universerpc::Id) -> Result<ProofType, Status> {
    convert::proof_type_from_proto(id.proof_type)
        .map_err(|e| Status::invalid_argument(e.to_string()))
}

/// Marshals a universe root, mapping conversion failures to internal
/// errors (a stored root always has a representable ID).
fn root_to_proto(
    root: &UniverseRoot,
) -> Result<universerpc::UniverseRoot, Status> {
    convert::universe_root_to_proto(root)
        .map_err(|e| Status::internal(e.to_string()))
}

/// Marshals a universe leaf into the RPC `AssetLeaf`. Only the fields
/// rust-tap tracks are filled: the raw proof (which peers decode for
/// the full asset, like Go's `unmarshalAssetLeaf`) plus a minimal
/// asset stub carrying the amount, asset ID and script key.
fn leaf_to_proto(leaf: &UniverseLeaf) -> universerpc::AssetLeaf {
    universerpc::AssetLeaf {
        asset: Some(taprpc::Asset {
            amount: leaf.amount,
            asset_genesis: Some(taprpc::GenesisInfo {
                asset_id: leaf.asset_id.0.to_vec(),
                ..Default::default()
            }),
            script_key: leaf.key.script_key.as_bytes().to_vec(),
            ..Default::default()
        }),
        proof: leaf.proof.clone(),
    }
}

/// Map key for `AssetRootResponse.universe_roots`; the format is
/// informational only (clients iterate values), mirroring Go's
/// `universe.Identifier.String()` shape.
fn root_map_key(root: &UniverseRoot) -> String {
    let id_hex = match &root.id.group_key {
        Some(gk) => hex(&gk.as_bytes()[1..]),
        None => hex(&root.id.asset_id.0),
    };
    format!("{}-{}", root.id.proof_type.as_str(), id_hex)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[tap_grpc::tonic::async_trait]
impl Universe for GrpcUniverseService {
    async fn multiverse_root(
        &self,
        _request: Request<universerpc::MultiverseRootRequest>,
    ) -> Result<Response<universerpc::MultiverseRootResponse>, Status> {
        // rust-tap backends do not maintain a multiverse tree over
        // their universes, so there is no root to serve.
        Err(Status::unimplemented(
            "MultiverseRoot is not implemented by this server",
        ))
    }

    async fn asset_roots(
        &self,
        request: Request<universerpc::AssetRootRequest>,
    ) -> Result<Response<universerpc::AssetRootResponse>, Status> {
        let request = request.into_inner();
        let (offset, limit) = validate_page(request.offset, request.limit)?;

        let (roots, has_more) = self
            .run_blocking(move |service| service.roots(offset, limit))
            .await?;

        let mut universe_roots =
            std::collections::HashMap::with_capacity(roots.len());
        for root in &roots {
            universe_roots.insert(root_map_key(root), root_to_proto(root)?);
        }

        Ok(Response::new(universerpc::AssetRootResponse {
            universe_roots,
            has_more,
        }))
    }

    async fn query_asset_roots(
        &self,
        request: Request<universerpc::AssetRootQuery>,
    ) -> Result<Response<universerpc::QueryRootResponse>, Status> {
        let request = request.into_inner();
        let id = request
            .id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("id must be set"))?;
        let selector = selector_from_proto(id)?;

        let result = self
            .run_blocking(move |service| service.query_roots(&selector))
            .await?;

        // tapd marshals an absent root as an empty message (see Go
        // marshalUniverseRoot / universe.IsEmptyRootResponse).
        let marshal = |root: Option<UniverseRoot>| -> Result<
            universerpc::UniverseRoot,
            Status,
        > {
            match root {
                Some(root) => root_to_proto(&root),
                None => Ok(universerpc::UniverseRoot::default()),
            }
        };

        Ok(Response::new(universerpc::QueryRootResponse {
            issuance_root: Some(marshal(result.issuance)?),
            transfer_root: Some(marshal(result.transfer)?),
        }))
    }

    async fn delete_asset_root(
        &self,
        _request: Request<universerpc::DeleteRootQuery>,
    ) -> Result<Response<universerpc::DeleteRootResponse>, Status> {
        Err(Status::unimplemented("DeleteAssetRoot is not implemented"))
    }

    async fn delete_asset_leaf(
        &self,
        _request: Request<universerpc::DeleteAssetLeafRequest>,
    ) -> Result<Response<universerpc::DeleteAssetLeafResponse>, Status> {
        Err(Status::unimplemented("DeleteAssetLeaf is not implemented"))
    }

    async fn asset_leaf_keys(
        &self,
        request: Request<universerpc::AssetLeafKeysRequest>,
    ) -> Result<Response<universerpc::AssetLeafKeyResponse>, Status> {
        let request = request.into_inner();
        let id = request
            .id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("id must be set"))?;
        let selector = selector_from_proto(id)?;
        let proof_type = required_proof_type(id)?;
        let (offset, limit) = validate_page(request.offset, request.limit)?;

        let (keys, has_more) = self
            .run_blocking(move |service| {
                service.leaf_keys(&selector, proof_type, offset, limit)
            })
            .await?;

        Ok(Response::new(universerpc::AssetLeafKeyResponse {
            asset_keys: keys
                .iter()
                .map(convert::leaf_key_to_proto)
                .collect(),
            has_more,
        }))
    }

    async fn asset_leaves(
        &self,
        request: Request<universerpc::AssetLeavesRequest>,
    ) -> Result<Response<universerpc::AssetLeafResponse>, Status> {
        let request = request.into_inner();
        let id = request
            .id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("id must be set"))?;
        let selector = selector_from_proto(id)?;
        let proof_type = required_proof_type(id)?;

        let leaves = self
            .run_blocking(move |service| {
                service.leaves(&selector, proof_type)
            })
            .await?;

        Ok(Response::new(universerpc::AssetLeafResponse {
            leaves: leaves.iter().map(leaf_to_proto).collect(),
            has_more: false,
        }))
    }

    async fn query_proof(
        &self,
        request: Request<universerpc::UniverseKey>,
    ) -> Result<Response<universerpc::AssetProofResponse>, Status> {
        let request = request.into_inner();
        let id = request
            .id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("id must be set"))?;
        let selector = selector_from_proto(id)?;
        let proof_type = required_proof_type(id)?;
        let leaf_key = convert::leaf_key_from_proto(
            request.leaf_key.as_ref().ok_or_else(|| {
                Status::invalid_argument("leaf_key must be set")
            })?,
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let key = leaf_key.clone();
        let found = self
            .run_blocking(move |service| {
                service.query_proof(&selector, proof_type, &key)
            })
            .await?;

        let (root, proof) = found
            .ok_or_else(|| Status::not_found(NO_PROOF_MSG))?;

        // Echo the request universe ID in the root (tapd sets
        // uniRoot.Id = req.Id in marshalUniverseProofLeaf).
        let universe_root = match root {
            Some(root) => {
                let mut proto = root_to_proto(&root)?;
                proto.id = Some(id.clone());
                Some(proto)
            }
            None => None,
        };

        Ok(Response::new(universerpc::AssetProofResponse {
            req: Some(request),
            universe_root,
            universe_inclusion_proof: proof.inclusion_proof.clone(),
            asset_leaf: Some(leaf_to_proto(&proof.leaf)),
            multiverse_root: None,
            multiverse_inclusion_proof: vec![],
            issuance_data: None,
        }))
    }

    async fn insert_proof(
        &self,
        request: Request<universerpc::AssetProof>,
    ) -> Result<Response<universerpc::AssetProofResponse>, Status> {
        let request = request.into_inner();
        let key = request
            .key
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("key must be set"))?;
        let id = key
            .id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("key.id must be set"))?;
        let leaf_key = convert::leaf_key_from_proto(
            key.leaf_key.as_ref().ok_or_else(|| {
                Status::invalid_argument("key.leaf_key must be set")
            })?,
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let raw_proof = request
            .asset_leaf
            .as_ref()
            .map(|leaf| leaf.proof.clone())
            .filter(|proof| !proof.is_empty())
            .ok_or_else(|| {
                Status::invalid_argument("asset_leaf.proof must be set")
            })?;

        // The service validates the proof against the asset ID it is
        // inserted under. Asset-ID requests carry it directly; for
        // group-key requests the asset ID comes from the proof itself
        // (which the service then cross-checks).
        let asset_id = match selector_from_proto(id)? {
            UniverseSelector::Asset(asset_id) => asset_id,
            UniverseSelector::Group(_) => {
                let proof = tap_primitives::proof::decode_proof(&raw_proof)
                    .map_err(|e| {
                        Status::invalid_argument(format!(
                            "proof does not decode: {}",
                            e
                        ))
                    })?;
                proof.asset.id()
            }
        };

        let (outpoint, script_key) =
            (leaf_key.outpoint, leaf_key.script_key);
        let (root, inserted) = self
            .run_blocking(move |service| {
                service.insert_proof(
                    &asset_id,
                    &outpoint,
                    &script_key,
                    &raw_proof,
                )
            })
            .await?;

        Ok(Response::new(universerpc::AssetProofResponse {
            req: Some(universerpc::UniverseKey {
                id: Some(id.clone()),
                leaf_key: Some(convert::leaf_key_to_proto(&LeafKey {
                    outpoint,
                    script_key,
                })),
            }),
            universe_root: Some(root_to_proto(&root)?),
            universe_inclusion_proof: inserted.inclusion_proof.clone(),
            asset_leaf: Some(leaf_to_proto(&inserted.leaf)),
            multiverse_root: None,
            multiverse_inclusion_proof: vec![],
            issuance_data: None,
        }))
    }

    async fn push_proof(
        &self,
        _request: Request<universerpc::PushProofRequest>,
    ) -> Result<Response<universerpc::PushProofResponse>, Status> {
        Err(Status::unimplemented("PushProof is not implemented"))
    }

    async fn info(
        &self,
        _request: Request<universerpc::InfoRequest>,
    ) -> Result<Response<universerpc::InfoResponse>, Status> {
        let info = self
            .run_blocking(move |service| service.info())
            .await?;
        Ok(Response::new(universerpc::InfoResponse {
            runtime_id: info.runtime_id,
        }))
    }

    async fn sync_universe(
        &self,
        _request: Request<universerpc::SyncRequest>,
    ) -> Result<Response<universerpc::SyncResponse>, Status> {
        Err(Status::unimplemented("SyncUniverse is not implemented"))
    }

    async fn list_federation_servers(
        &self,
        _request: Request<universerpc::ListFederationServersRequest>,
    ) -> Result<Response<universerpc::ListFederationServersResponse>, Status>
    {
        Err(Status::unimplemented(
            "ListFederationServers is not implemented",
        ))
    }

    async fn add_federation_server(
        &self,
        _request: Request<universerpc::AddFederationServerRequest>,
    ) -> Result<Response<universerpc::AddFederationServerResponse>, Status>
    {
        Err(Status::unimplemented(
            "AddFederationServer is not implemented",
        ))
    }

    async fn delete_federation_server(
        &self,
        _request: Request<universerpc::DeleteFederationServerRequest>,
    ) -> Result<Response<universerpc::DeleteFederationServerResponse>, Status>
    {
        Err(Status::unimplemented(
            "DeleteFederationServer is not implemented",
        ))
    }

    async fn universe_stats(
        &self,
        _request: Request<universerpc::StatsRequest>,
    ) -> Result<Response<universerpc::StatsResponse>, Status> {
        Err(Status::unimplemented("UniverseStats is not implemented"))
    }

    async fn query_asset_stats(
        &self,
        _request: Request<universerpc::AssetStatsQuery>,
    ) -> Result<Response<universerpc::UniverseAssetStats>, Status> {
        Err(Status::unimplemented("QueryAssetStats is not implemented"))
    }

    async fn query_events(
        &self,
        _request: Request<universerpc::QueryEventsRequest>,
    ) -> Result<Response<universerpc::QueryEventsResponse>, Status> {
        Err(Status::unimplemented("QueryEvents is not implemented"))
    }

    async fn set_federation_sync_config(
        &self,
        _request: Request<universerpc::SetFederationSyncConfigRequest>,
    ) -> Result<
        Response<universerpc::SetFederationSyncConfigResponse>,
        Status,
    > {
        Err(Status::unimplemented(
            "SetFederationSyncConfig is not implemented",
        ))
    }

    async fn query_federation_sync_config(
        &self,
        _request: Request<universerpc::QueryFederationSyncConfigRequest>,
    ) -> Result<
        Response<universerpc::QueryFederationSyncConfigResponse>,
        Status,
    > {
        Err(Status::unimplemented(
            "QueryFederationSyncConfig is not implemented",
        ))
    }

    async fn ignore_asset_out_point(
        &self,
        _request: Request<universerpc::IgnoreAssetOutPointRequest>,
    ) -> Result<Response<universerpc::IgnoreAssetOutPointResponse>, Status>
    {
        Err(Status::unimplemented(
            "IgnoreAssetOutPoint is not implemented",
        ))
    }

    async fn update_supply_commit(
        &self,
        _request: Request<universerpc::UpdateSupplyCommitRequest>,
    ) -> Result<Response<universerpc::UpdateSupplyCommitResponse>, Status>
    {
        Err(Status::unimplemented(
            "UpdateSupplyCommit is not implemented",
        ))
    }

    async fn fetch_supply_commit(
        &self,
        _request: Request<universerpc::FetchSupplyCommitRequest>,
    ) -> Result<Response<universerpc::FetchSupplyCommitResponse>, Status>
    {
        Err(Status::unimplemented(
            "FetchSupplyCommit is not implemented",
        ))
    }

    async fn fetch_supply_leaves(
        &self,
        _request: Request<universerpc::FetchSupplyLeavesRequest>,
    ) -> Result<Response<universerpc::FetchSupplyLeavesResponse>, Status>
    {
        Err(Status::unimplemented(
            "FetchSupplyLeaves is not implemented",
        ))
    }

    async fn insert_supply_commit(
        &self,
        _request: Request<universerpc::InsertSupplyCommitRequest>,
    ) -> Result<Response<universerpc::InsertSupplyCommitResponse>, Status>
    {
        Err(Status::unimplemented(
            "InsertSupplyCommit is not implemented",
        ))
    }
}

/// Builds the tonic router serving the universe gRPC service (e.g. to
/// mount on a custom listener in tests).
pub fn grpc_router(service: UniverseService) -> Router {
    Server::builder()
        .add_service(GrpcUniverseService::new(service).into_server())
}

/// Binds `addr` and serves the universe gRPC API until shutdown.
pub async fn serve_grpc(
    addr: SocketAddr,
    service: UniverseService,
) -> Result<(), tap_grpc::tonic::transport::Error> {
    grpc_router(service).serve(addr).await
}

/// Binds `addr` and serves the universe gRPC API over TLS until
/// shutdown. `cert_pem`/`key_pem` are the PEM-encoded server
/// certificate (chain) and private key.
///
/// TLS matters for tapd interop: tapd's universe-RPC proof courier
/// (proof/courier.go `serverDialOpts`) always dials with TLS
/// (certificate verification disabled), so a plaintext listener can
/// never receive couriered proofs from tapd. Any self-signed
/// certificate works.
pub async fn serve_grpc_tls(
    addr: SocketAddr,
    service: UniverseService,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(), tap_grpc::tonic::transport::Error> {
    use tap_grpc::tonic::transport::{Identity, ServerTlsConfig};

    Server::builder()
        .tls_config(
            ServerTlsConfig::new()
                .identity(Identity::from_pem(cert_pem, key_pem)),
        )?
        .add_service(GrpcUniverseService::new(service).into_server())
        .serve(addr)
        .await
}
