//! Compiles the vendored tapd protos (see `proto/README.md` for the
//! source commit) into Rust modules with tonic/prost.
//!
//! Requires `protoc`; set the `PROTOC` environment variable to point at
//! a specific binary, otherwise `protoc` is resolved from `PATH` (with
//! a fallback to the Homebrew install location on macOS).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // prost-build resolves protoc from the PROTOC env var or PATH. If
    // neither works, try the common Homebrew location before failing.
    if std::env::var_os("PROTOC").is_none()
        && which_protoc().is_none()
        && std::path::Path::new("/opt/homebrew/bin/protoc").exists()
    {
        std::env::set_var("PROTOC", "/opt/homebrew/bin/protoc");
    }

    let protos = [
        "proto/tapcommon.proto",
        "proto/taprootassets.proto",
        "proto/universerpc/universe.proto",
        "proto/authmailboxrpc/mailbox.proto",
    ];
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &["proto"])?;

    Ok(())
}

/// Returns the path of `protoc` on `PATH`, if any.
fn which_protoc() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("protoc"))
        .find(|candidate| candidate.is_file())
}
