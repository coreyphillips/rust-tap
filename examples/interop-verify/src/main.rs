// interop-verify: decode a Taproot Assets proof file (TAPF, as exported
// by `tapcli proofs export`) and run the full rust-tap verification
// pipeline (`File::verify`) with REAL chain verification: block headers
// are checked against a live chain through an Esplora HTTP API.
//
// Usage:
//   interop-verify <proof_file> [esplora_url]
//
// The esplora URL defaults to http://127.0.0.1:3002 (the regtest
// electrs instance started by the scripts in interop/).
//
// Exit code 0 = the proof file fully verified (structure, TLV decoding,
// commitment inclusion/exclusion proofs, tx merkle proof against the
// header's merkle root, and the header against the live chain).

use tap_primitives::proof::file::File;
use tap_primitives::proof::types::BlockHeader;
use tap_primitives::proof::verify::{
    ChainLookup, DefaultMerkleVerifier, GroupVerifier, HeaderVerifier,
    ProofVerificationOptions, VerifierCtx,
};
use tap_primitives::proof::ProofError;
use tap_primitives::asset::SerializedKey;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Minimal Esplora REST client (same endpoints the quickstart uses).
struct Esplora {
    base_url: String,
}

impl Esplora {
    fn new(url: &str) -> Self {
        Esplora {
            base_url: url.trim_end_matches('/').to_string(),
        }
    }

    fn get(&self, path: &str) -> Result<String, ProofError> {
        let url = format!("{}{}", self.base_url, path);
        ureq::get(&url)
            .call()
            .map_err(|e| {
                ProofError::VerificationFailed(format!("HTTP {}: {}", url, e))
            })?
            .into_string()
            .map_err(|e| {
                ProofError::VerificationFailed(format!("read {}: {}", url, e))
            })
    }
}

/// Verifies proof block headers against the live chain: the header's
/// double-SHA256 hash must equal the chain's block hash at the claimed
/// height.
impl HeaderVerifier for &Esplora {
    fn verify_header(
        &self,
        header: &BlockHeader,
        height: u32,
    ) -> Result<(), ProofError> {
        let expect_hex = self.get(&format!("/block-height/{}", height))?;
        let expect_hex = expect_hex.trim();

        // Esplora returns the display (reversed) hex hash.
        let mut got = header.block_hash();
        got.reverse();
        let got_hex = hex_encode(&got);

        if got_hex != expect_hex {
            return Err(ProofError::VerificationFailed(format!(
                "header mismatch at height {}: proof {} vs chain {}",
                height, got_hex, expect_hex
            )));
        }
        Ok(())
    }
}

impl ChainLookup for &Esplora {
    fn current_height(&self) -> Result<u32, ProofError> {
        self.get("/blocks/tip/height")?.trim().parse().map_err(|e| {
            ProofError::VerificationFailed(format!("parse height: {}", e))
        })
    }
}

/// Group keys reveal their derivation inside the proof itself
/// (`group_key_reveal` is checked by the pipeline); a universe-style
/// "is this issuance known" check is out of scope for a pure chain
/// verification, so accept all group keys here (matches verifying a
/// proof from a universe we just fetched it from).
struct AcceptAllGroups;

impl GroupVerifier for AcceptAllGroups {
    fn verify_group_key(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: interop-verify <proof_file> [esplora_url]");
        std::process::exit(2);
    }
    let proof_path = &args[1];
    let esplora_url = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("http://127.0.0.1:3002");

    let data = std::fs::read(proof_path).unwrap_or_else(|e| {
        eprintln!("FAIL: read {}: {}", proof_path, e);
        std::process::exit(1);
    });

    // Raw single proofs (TAPP magic) are wrapped into a one-entry file.
    let file = if data.len() >= 4 && data[..4] == [0x54, 0x41, 0x50, 0x50] {
        let mut f = File::new();
        f.append_proof(data);
        f
    } else {
        match File::decode(&data) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("FAIL: proof file decode: {:?}", e);
                std::process::exit(1);
            }
        }
    };

    println!(
        "Decoded proof file: version {}, {} proof(s)",
        file.version,
        file.num_proofs()
    );

    if !file.verify_hash_chain() {
        eprintln!("FAIL: proof file hash chain is broken");
        std::process::exit(1);
    }
    println!("Hash chain OK.");

    let esplora = Esplora::new(esplora_url);
    let ctx = VerifierCtx::new(
        &esplora,
        DefaultMerkleVerifier,
        AcceptAllGroups,
        &esplora,
    );
    let opts = ProofVerificationOptions::default();

    match file.verify(&ctx, &opts) {
        Ok(snapshot) => {
            let asset = &snapshot.asset;
            println!("VERIFY OK");
            println!("  asset id:     {}", hex_encode(asset.genesis.id().as_bytes()));
            println!("  name:         {}", asset.genesis.tag);
            println!("  type:         {:?}", asset.genesis.asset_type);
            println!("  amount:       {}", asset.amount);
            println!("  script key:   {}", hex_encode(&asset.script_key.pub_key.0));
            println!("  anchor height:{}", snapshot.anchor_block_height);
            let mut bh = snapshot.anchor_block_hash;
            bh.reverse();
            println!("  anchor block: {}", hex_encode(&bh));
            let mut txid = snapshot.out_point.txid;
            txid.reverse();
            println!(
                "  anchor point: {}:{}",
                hex_encode(&txid),
                snapshot.out_point.vout
            );
        }
        Err(e) => {
            eprintln!("FAIL: verification error: {:?}", e);
            std::process::exit(1);
        }
    }
}
