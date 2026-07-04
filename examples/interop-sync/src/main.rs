// interop-sync: sync an asset's issuance proofs from a REAL tapd
// universe server over its native gRPC interface (TLS + macaroon),
// using rust-tap's GrpcUniverseClient + SimpleSyncer.
//
// Usage:
//   interop-sync <grpc_uri> <tls_cert_path> <macaroon_path> <asset_id_hex>
//
// e.g.
//   interop-sync https://127.0.0.1:10029 \
//       $TAPD_DIR/tls.cert \
//       $TAPD_DIR/data/regtest/admin.macaroon \
//       0dc6c394...
//
// Pass "-" for the macaroon path to send no macaroon (works when tapd
// runs with --universe.public-access=r/rw, which whitelists universe
// queries).
//
// Exit code 0 = the remote root was fetched, all missing leaves were
// downloaded, each leaf's proof passed rust-tap verification, the
// leaves were inserted into a local in-memory universe, and the local
// root now matches the remote root.

use tap_grpc::{ConnectOptions, GrpcUniverseClient};
use tap_universe::DiffEngine;
use tap_universe::{
    MemoryUniverseBackend, SimpleSyncer, Syncer, UniverseBackend,
};
use tap_universe::types::{ProofType, UniverseId};
use tap_primitives::asset::AssetId;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, s.len()));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex: {}", e))?;
    }
    Ok(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "Usage: interop-sync <grpc_uri> <tls_cert_path> \
             <macaroon_path> <asset_id_hex>"
        );
        std::process::exit(2);
    }
    let uri = &args[1];
    let tls_cert_path = &args[2];
    let macaroon_path = &args[3];
    let asset_id_hex = &args[4];

    let tls_cert_pem = std::fs::read(tls_cert_path).unwrap_or_else(|e| {
        eprintln!("FAIL: read {}: {}", tls_cert_path, e);
        std::process::exit(1);
    });
    let macaroon_hex = if macaroon_path == "-" {
        None
    } else {
        let bytes = std::fs::read(macaroon_path).unwrap_or_else(|e| {
            eprintln!("FAIL: read {}: {}", macaroon_path, e);
            std::process::exit(1);
        });
        Some(hex_encode(&bytes))
    };
    let asset_id = match hex_decode_array::<32>(asset_id_hex) {
        Ok(id) => AssetId(id),
        Err(e) => {
            eprintln!("FAIL: bad asset id: {}", e);
            std::process::exit(1);
        }
    };

    let client = match GrpcUniverseClient::connect_with_options(
        uri,
        ConnectOptions {
            tls_cert_pem: Some(tls_cert_pem),
            tls_domain: None,
            macaroon_hex,
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FAIL: connect {}: {}", uri, e);
            std::process::exit(1);
        }
    };

    match client.info() {
        Ok(runtime_id) => {
            println!("Connected to {} (runtime id {})", uri, runtime_id)
        }
        Err(e) => {
            eprintln!("FAIL: info RPC: {}", e);
            std::process::exit(1);
        }
    }

    let id = UniverseId {
        asset_id,
        group_key: None,
        proof_type: ProofType::Issuance,
    };

    // SimpleSyncer::new() verifies every fetched leaf's proof with the
    // full rust-tap pipeline before inserting it locally.
    let mut local = MemoryUniverseBackend::new();
    let syncer = SimpleSyncer::new();
    let diff = match syncer.sync_universe(&mut local, &client, &id) {
        Ok(diff) => diff,
        Err(e) => {
            eprintln!("FAIL: sync: {}", e);
            std::process::exit(1);
        }
    };

    println!(
        "Synced {} new leaf/leaves for asset {}",
        diff.new_leaves.len(),
        asset_id_hex
    );
    for leaf in &diff.new_leaves {
        let mut txid = leaf.key.outpoint.txid;
        txid.reverse();
        println!(
            "  leaf: amount {} outpoint {}:{} script key {} ({} proof bytes)",
            leaf.amount,
            hex_encode(&txid),
            leaf.key.outpoint.vout,
            hex_encode(&leaf.key.script_key.0),
            leaf.proof.len(),
        );
    }

    if diff.new_leaves.is_empty() {
        eprintln!("FAIL: nothing synced (asset unknown to the remote?)");
        std::process::exit(1);
    }

    // The local root must now match the remote root.
    let local_root = local.root_node(&id).unwrap_or_else(|e| {
        eprintln!("FAIL: local root: {}", e);
        std::process::exit(1);
    });
    let remote_root = client.root_node(&id).unwrap_or_else(|e| {
        eprintln!("FAIL: remote root: {}", e);
        std::process::exit(1);
    });
    if local_root.root_hash != remote_root.root_hash
        || local_root.root_sum != remote_root.root_sum
    {
        eprintln!(
            "FAIL: root mismatch after sync: local {}/{} vs remote {}/{}",
            hex_encode(local_root.root_hash.as_bytes()),
            local_root.root_sum,
            hex_encode(remote_root.root_hash.as_bytes()),
            remote_root.root_sum,
        );
        std::process::exit(1);
    }

    println!(
        "SYNC OK: local root {} (sum {}) matches remote",
        hex_encode(local_root.root_hash.as_bytes()),
        local_root.root_sum
    );
}
