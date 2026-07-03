// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! `tap-universe-server`: serves a SQLite-backed Taproot Assets
//! universe over tapd's REST gateway paths.
//!
//! Configuration (flags take precedence over environment variables):
//!
//! - `--listen <addr>` / `TAP_SERVER_LISTEN`: REST listen address
//!   (default `127.0.0.1:8080`)
//! - `--db <path>` / `TAP_SERVER_DB`: SQLite database path
//!   (default `tap-universe.db3`)
//! - `--grpc-listen <addr>` / `TAP_SERVER_GRPC_LISTEN`: universe gRPC
//!   listen address (feature `grpc`; disabled when unset). This is
//!   the tapd-native federation endpoint.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tap_persist::sqlite::SqliteDb;
use tap_persist::universe_store::SqliteUniverseBackend;
use tap_server::UniverseService;

/// Reads a `--flag value` argument, falling back to an environment
/// variable, then a default.
fn config_value(
    args: &[String],
    flag: &str,
    env: &str,
    default: &str,
) -> String {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        if let Some(value) = args.get(pos + 1) {
            return value.clone();
        }
    }
    std::env::var(env).unwrap_or_else(|_| default.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "tap-universe-server: Taproot Assets universe REST server\n\n\
             Usage: tap-universe-server [--listen <addr>] [--db <path>]\n\n\
             Options:\n\
             \x20 --listen <addr>       REST listen address (env TAP_SERVER_LISTEN, default 127.0.0.1:8080)\n\
             \x20 --db <path>           SQLite database path (env TAP_SERVER_DB, default tap-universe.db3)\n\
             \x20 --grpc-listen <addr>  Universe gRPC listen address (env TAP_SERVER_GRPC_LISTEN, feature grpc, disabled when unset)"
        );
        return Ok(());
    }

    let listen = config_value(
        &args,
        "--listen",
        "TAP_SERVER_LISTEN",
        "127.0.0.1:8080",
    );
    let db_path =
        config_value(&args, "--db", "TAP_SERVER_DB", "tap-universe.db3");

    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| format!("bad listen address {:?}: {}", listen, e))?;

    let grpc_listen = config_value(
        &args,
        "--grpc-listen",
        "TAP_SERVER_GRPC_LISTEN",
        "",
    );
    let grpc_addr: Option<SocketAddr> = if grpc_listen.is_empty() {
        None
    } else {
        Some(grpc_listen.parse().map_err(|e| {
            format!("bad gRPC listen address {:?}: {}", grpc_listen, e)
        })?)
    };
    #[cfg(not(feature = "grpc"))]
    if grpc_addr.is_some() {
        return Err(
            "--grpc-listen requires building with the `grpc` feature"
                .into(),
        );
    }

    let db = Arc::new(SqliteDb::open(&db_path)?);
    let backend = SqliteUniverseBackend::new(db);
    let service = UniverseService::new(Arc::new(Mutex::new(backend)));

    println!(
        "tap-universe-server listening on http://{} (db: {})",
        addr, db_path
    );
    if let Some(grpc_addr) = grpc_addr {
        println!(
            "tap-universe-server serving universe gRPC on {}",
            grpc_addr
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        // The gRPC server (when configured) runs alongside REST in the
        // same runtime; either exiting is fatal.
        #[cfg(feature = "grpc")]
        if let Some(grpc_addr) = grpc_addr {
            let grpc_service = service.clone();
            tokio::select! {
                result = tap_server::serve(addr, service) => {
                    result.map_err(Box::<dyn std::error::Error>::from)
                }
                result = tap_server::grpc::serve_grpc(
                    grpc_addr,
                    grpc_service,
                ) => {
                    result.map_err(Box::<dyn std::error::Error>::from)
                }
            }
        } else {
            tap_server::serve(addr, service)
                .await
                .map_err(Box::<dyn std::error::Error>::from)
        }
        #[cfg(not(feature = "grpc"))]
        {
            tap_server::serve(addr, service)
                .await
                .map_err(Box::<dyn std::error::Error>::from)
        }
    })?;
    Ok(())
}
