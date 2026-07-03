// tap-quickstart: Interactive Taproot Assets wallet backed by a JSON state file.
//
// Usage:
//   cargo run -p tap-quickstart -- "your twelve word mnemonic"           # interactive menu
//   cargo run -p tap-quickstart -- "your twelve word mnemonic" mint "TokenName" 1000000
//   cargo run -p tap-quickstart -- "your twelve word mnemonic" status
//   cargo run -p tap-quickstart -- "your twelve word mnemonic" list
//   cargo run -p tap-quickstart -- "your twelve word mnemonic" receive <asset_id> <amount>
//   cargo run -p tap-quickstart -- "your twelve word mnemonic" send <asset_id> <amount> <address>
//   cargo run -p tap-quickstart -- "your twelve word mnemonic" sync

mod state;
mod wallet;

use std::io::{self, Write};
use std::path::PathBuf;

use tap_node::*;
use tap_primitives::asset::AssetId;

use state::WalletState;
use wallet::{create_bdk_wallet_with_path, create_key_ring, EsploraChain, StubLdk, StubOracle};

// ============================================================================
// Configuration
// ============================================================================

const ESPLORA_URL: &str = "https://blockstream.info/testnet/api";
const DATA_DIR: &str = "./tap-wallets";

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: tap-quickstart \"<mnemonic>\" [command] [args...]");
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  (none)                         Interactive menu");
        eprintln!("  mint <name> <amount>           Mint a new asset");
        eprintln!("  status                         Check pending mints");
        eprintln!("  list                           List owned assets");
        eprintln!("  receive <asset_id> <amount>    Generate receive address");
        eprintln!("  send <asset_id> <amount> <addr> Send an asset");
        eprintln!("  sync                           Sync wallet with chain");
        eprintln!("  deep-sync                      Deep scan (stop gap 200, for imported mnemonics)");
        eprintln!();
        eprintln!("The mnemonic is always required and never stored.");
        std::process::exit(1);
    }

    let mnemonic = &args[1];

    // Derive a fingerprint from the mnemonic so each wallet gets its own
    // data directory. Uses first 8 hex chars of SHA256(mnemonic).
    let fingerprint = wallet_fingerprint(mnemonic);
    let wallet_dir = format!("{}/{}", DATA_DIR, fingerprint);
    let state_file = format!("{}/state.json", wallet_dir);
    let bdk_db_path = format!("{}/bdk-wallet.dat", wallet_dir);
    std::fs::create_dir_all(&wallet_dir).expect("Failed to create wallet dir");

    // Load or create state file.
    let mut state = WalletState::load(&state_file);

    // Set up backends.
    println!("Wallet: {}", wallet_dir);
    let bdk_wallet = wallet::create_bdk_wallet_with_path(mnemonic, ESPLORA_URL, &bdk_db_path);
    let key_ring = create_key_ring(mnemonic);
    let chain = EsploraChain::new(ESPLORA_URL);

    // Sync BDK wallet.
    // Use deep scan (stop gap 200) if "deep-sync" command, otherwise normal (20).
    let is_deep = args.len() > 2 && args[2] == "deep-sync";
    let stop_gap = if is_deep { 50 } else { 20 };
    if is_deep {
        print!("Deep syncing (stop gap {})... ", stop_gap);
    } else {
        print!("Syncing... ");
    }
    io::stdout().flush().unwrap();
    match bdk_wallet.sync(stop_gap) {
        Ok(()) => {
            let (confirmed, pending) = bdk_wallet.balance();
            state.btc_confirmed = confirmed;
            state.btc_pending = pending;
            println!("done.");
        }
        Err(e) => println!("sync failed: {}", e),
    }

    let address = bdk_wallet.next_address();
    state.btc_address = address.clone();
    println!("Address: {}", address);
    state.save();

    // Build tap-node.
    let config = TapNodeConfig {
        network: TapNetwork::Testnet,
        db_path: Some(PathBuf::from(format!("{}/assets.db", wallet_dir))),
        default_conf_target: 3,
        ..Default::default()
    };

    // `start()` takes an Arc so its background worker (confirmation
    // watching, universe sync) can hold a weak handle to the node.
    let node = std::sync::Arc::new(
        TapNodeBuilder::new(config)
            .set_chain_bridge(chain)
            .set_wallet_anchor(bdk_wallet)
            .set_key_ring(key_ring)
            .set_ldk_ops(StubLdk)
            .set_price_oracle(StubOracle)
            .build()
            .expect("Failed to build node"),
    );

    node.clone().start().expect("Failed to start node");

    // Route to subcommand or interactive menu.
    if args.len() > 2 {
        run_command(&node, &mut state, &args[2..]);
    } else {
        run_interactive(&node, &mut state);
    }

    state.save();
    node.stop().expect("Failed to stop node");
}

// ============================================================================
// Subcommand dispatch
// ============================================================================

fn run_command<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    state: &mut WalletState,
    args: &[String],
) where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    match args[0].as_str() {
        "mint" => {
            if args.len() < 3 {
                eprintln!("Usage: mint <name> <amount>");
                return;
            }
            let name = &args[1];
            let amount: u64 = args[2].parse().expect("Invalid amount");
            cmd_mint(node, state, name, amount);
        }
        "status" => cmd_status(state),
        "list" => cmd_list(state),
        "receive" => {
            if args.len() < 3 {
                eprintln!("Usage: receive <asset_id_hex> <amount>");
                return;
            }
            cmd_receive(node, state, &args[1], &args[2]);
        }
        "send" => {
            if args.len() < 4 {
                eprintln!("Usage: send <asset_id_hex> <amount> <tap_address>");
                return;
            }
            cmd_send(node, state, &args[1], &args[2], &args[3]);
        }
        "sync" => cmd_sync(state),
        "deep-sync" => {
            // Already handled during startup sync above.
            cmd_sync(state);
        }
        other => eprintln!("Unknown command: {}", other),
    }
}

// ============================================================================
// Interactive menu
// ============================================================================

fn run_interactive<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    state: &mut WalletState,
) where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    println!();
    println!("=== tap-node wallet ===");
    println!();

    loop {
        print_summary(state);
        println!();
        println!("  1. Mint a new asset");
        println!("  2. Check pending mints");
        println!("  3. List my assets");
        println!("  4. Send an asset");
        println!("  5. Generate receive address");
        println!("  6. Sync wallet");
        println!("  7. Deep sync (imported mnemonic recovery)");
        println!("  8. Exit");
        println!();

        let choice = prompt("> ");
        println!();

        match choice.trim() {
            "1" => {
                let name = prompt("Asset name: ");
                let amount_str = prompt("Amount (1 for collectible): ");
                let amount: u64 = match amount_str.trim().parse() {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Invalid amount.");
                        continue;
                    }
                };
                cmd_mint(node, state, name.trim(), amount);
            }
            "2" => cmd_status(state),
            "3" => cmd_list(state),
            "4" => {
                let asset_id = prompt("Asset ID (hex): ");
                let amount = prompt("Amount: ");
                let address = prompt("Recipient TAP address: ");
                cmd_send(
                    node,
                    state,
                    asset_id.trim(),
                    amount.trim(),
                    address.trim(),
                );
            }
            "5" => {
                let asset_id = prompt("Asset ID (hex): ");
                let amount = prompt("Amount: ");
                cmd_receive(node, state, asset_id.trim(), amount.trim());
            }
            "6" => cmd_sync(state),
            "7" => {
                println!("To deep sync, restart with the deep-sync command:");
                println!("  cargo run -p tap-quickstart -- \"<mnemonic>\" deep-sync");
                println!("This scans 200 addresses deep to find all funds.");
            }
            "8" | "q" | "exit" | "quit" => {
                println!("Goodbye.");
                break;
            }
            _ => println!("Invalid choice."),
        }
        println!();
    }
}

// ============================================================================
// Commands
// ============================================================================

fn cmd_mint<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    state: &mut WalletState,
    name: &str,
    amount: u64,
) where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    if state.btc_confirmed == 0 {
        println!("No BTC balance. Fund your wallet first:");
        println!("  Address: {}", state.btc_address);
        println!("  Faucets: https://coinfaucet.eu/en/btc-testnet/");
        return;
    }

    println!("Minting {} units of '{}'...", amount, name);

    if amount == 1 {
        if let Err(e) = node.queue_mint(Seedling::new_collectible(name.into())) {
            println!("Failed to queue: {}", e);
            return;
        }
    } else {
        if let Err(e) = node.queue_mint(Seedling::new_normal(name.into(), amount)) {
            println!("Failed to queue: {}", e);
            return;
        }
    }

    match node.finalize_mint() {
        Ok(result) => {
            let txid_hex = result
                .txid
                .map(|t| hex_encode(&t))
                .unwrap_or_else(|| "unknown".into());

            println!("Mint broadcast! Txid: {}", txid_hex);

            let internal_key_hex = hex_encode(result.internal_key.as_bytes());
            let signed_tx_hex = hex_encode(&result.signed_tx);
            let genesis_txid_hex = hex_encode(&result.genesis_point.txid);
            let genesis_vout = result.genesis_point.vout;
            let funded_psbt_hex = hex_encode(&result.funded_psbt);

            for asset in &result.assets {
                println!("  {} -- {} units", asset.name, asset.amount);
                let mint = state::MintRecord {
                    name: asset.name.clone(),
                    amount: asset.amount,
                    asset_id: hex_encode(asset.asset_id.as_bytes()),
                    txid: txid_hex.clone(),
                    status: "broadcast".into(),
                    block_height: None,
                    block_hash: None,
                    internal_key: Some(internal_key_hex.clone()),
                    script_key: Some(hex_encode(asset.script_key.as_bytes())),
                    signed_tx_hex: Some(signed_tx_hex.clone()),
                    genesis_txid: Some(genesis_txid_hex.clone()),
                    genesis_vout: Some(genesis_vout),
                    funded_psbt_hex: Some(funded_psbt_hex.clone()),
                    tap_output_index: Some(result.tap_output_index),
                };
                state.mints.push(mint);
            }

            state.save();
        }
        Err(TapNodeError::Chain(ChainError::PsbtFailed(ref msg)))
            if msg.contains("InsufficientFunds") =>
        {
            println!("Insufficient BTC. Need ~3000+ sats for fees.");
            println!("  Your balance: {} sats", state.btc_confirmed);
        }
        Err(e) => println!("Mint failed: {}", e),
    }
}

fn cmd_status(state: &mut WalletState) {
    if state.mints.is_empty() {
        println!("No mints recorded.");
        return;
    }

    let chain = wallet::EsploraChain::new(ESPLORA_URL);
    let mut updated = false;

    for mint in &mut state.mints {
        println!(
            "{} -- {} units | asset_id: {}",
            mint.name, mint.amount, mint.asset_id
        );
        println!("  txid: {}", mint.txid);

        if mint.status == "registered" {
            println!("  status: registered (visible on Terminal)");
        } else if mint.status == "broadcast" || mint.status == "confirmed" {
            // Check for confirmation (or re-register if confirmed but not yet registered).
            if mint.status == "broadcast" {
                print!("  Checking confirmation... ");
                io::stdout().flush().unwrap();

                match chain.get_tx_status(&mint.txid) {
                    Ok(status) if status.confirmed => {
                        println!(
                            "confirmed at block {}!",
                            status.block_height
                        );
                        mint.status = "confirmed".into();
                        mint.block_height = Some(status.block_height);
                        mint.block_hash = Some(status.block_hash.clone());
                        updated = true;
                    }
                    Ok(_) => {
                        println!("not yet confirmed.");
                        continue;
                    }
                    Err(e) => {
                        println!("check failed: {}", e);
                        continue;
                    }
                }
            }

            // At this point, mint is confirmed. Try to register.
            let block_hash = mint.block_hash.clone().unwrap_or_default();
            let block_height = mint.block_height.unwrap_or(0);

            if block_hash.is_empty() {
                // We have "confirmed" status from a previous run but no block data.
                // Re-check to get the block hash.
                print!("  Fetching confirmation data... ");
                io::stdout().flush().unwrap();
                match chain.get_tx_status(&mint.txid) {
                    Ok(status) if status.confirmed => {
                        println!("block {}.", status.block_height);
                        mint.block_height = Some(status.block_height);
                        mint.block_hash = Some(status.block_hash.clone());
                        updated = true;
                    }
                    _ => {
                        println!("failed.");
                        continue;
                    }
                }
            }

            let block_hash = mint.block_hash.clone().unwrap_or_default();
            let block_height = mint.block_height.unwrap_or(0);

            match build_and_register_proof(
                &chain, mint, &block_hash, block_height,
            ) {
                Ok(()) => {
                    mint.status = "registered".into();
                    updated = true;
                    println!("  Registered with universe server!");
                }
                Err(e) => {
                    println!("  Registration failed: {}", e);
                    println!("  Run option 2 again to retry.");
                }
            }
        } else {
            println!("  status: {}", mint.status);
        }
        println!();
    }

    if updated {
        state.save();
    }
}

/// Builds a genesis proof from confirmed block data and registers it
/// with Lightning Labs' testnet universe server.
fn build_and_register_proof(
    chain: &wallet::EsploraChain,
    mint: &state::MintRecord,
    block_hash: &str,
    block_height: u32,
) -> Result<(), String> {
    use tap_primitives::asset::*;
    use tap_primitives::commitment::asset_commitment::{
        asset_commitment_key, asset_leaf, tap_commitment_key,
        AssetCommitment,
    };
    use tap_primitives::commitment::proof::{
        AssetProof, CommitmentProof, TaprootAssetProof,
    };
    use tap_primitives::commitment::{TapCommitment, TapCommitmentVersion};
    use tap_primitives::mssmt::{DefaultStore, FullTree};
    use tap_primitives::proof::encode::encode_proof;
    use tap_primitives::proof::types::*;

    // Parse saved proof data.
    let internal_key_bytes = mint
        .internal_key
        .as_ref()
        .ok_or("no internal_key saved -- re-mint to fix")?;
    let internal_key = SerializedKey(wallet::hex_decode_array::<33>(internal_key_bytes)?);

    let script_key_bytes = mint
        .script_key
        .as_ref()
        .ok_or("no script_key saved -- re-mint to fix")?;
    let script_key = SerializedKey(wallet::hex_decode_array::<33>(script_key_bytes)?);

    // Fetch block data.
    print!("  Fetching block data... ");
    io::stdout().flush().unwrap();
    let block = chain.get_block_data(block_hash, block_height)?;
    println!("done ({} txs in block).", block.txids.len());

    // Find tx and build merkle proof.
    let tx_index = block
        .txids
        .iter()
        .position(|t| t == &mint.txid)
        .ok_or_else(|| format!("tx {} not found in block", mint.txid))?;
    let merkle_proof = build_tx_merkle_proof(&block.txids, tx_index)?;

    let header = BlockHeader(block.header);
    let merkle_root = header.merkle_root();
    let mut tx_hash = wallet::hex_decode_array::<32>(&mint.txid)?;
    tx_hash.reverse();

    if !merkle_proof.verify(&tx_hash, &merkle_root) {
        return Err("merkle proof verification failed".into());
    }
    println!("  Merkle proof verified.");

    // Get raw tx (prefer saved, fallback to fetch).
    let raw_tx = if let Some(ref hex) = mint.signed_tx_hex {
        wallet::hex_decode_vec(hex)?
    } else {
        chain.get_raw_tx(&mint.txid)?
    };
    let raw_tx_for_verify = raw_tx.clone();

    // The on-chain commitment was built with the real genesis point
    // (discovered via two-pass in finalize_mint). Use the saved value.
    let genesis_txid_hex = mint
        .genesis_txid
        .as_ref()
        .ok_or("no genesis_txid saved -- re-mint with latest code")?;
    let genesis_txid = wallet::hex_decode_array::<32>(genesis_txid_hex)?;
    let genesis_vout = mint.genesis_vout.unwrap_or(0);
    let commitment_genesis_point = OutPoint {
        txid: genesis_txid,
        vout: genesis_vout,
    };

    // Find which output index has the TAP commitment (the 330-sat output).
    // BDK may reorder outputs, so we can't assume index 0.
    // Prefer the saved value (matches what was used to build the commitment);
    // fall back to scanning the tx for backwards compatibility.
    let tap_output_index = mint.tap_output_index
        .map(Ok)
        .unwrap_or_else(|| find_tap_output_index(&raw_tx))?;

    // The proof's prev_out must be an input of the anchor tx (the UTXO being
    // spent). The server checks TxSpendsPrevOut(anchor_tx, prev_out).
    // Extract the first input from the anchor transaction.
    let prev_out = {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw_tx)
            .map_err(|e| format!("tx parse for prev_out: {}", e))?;
        let first_input = tx.input.first()
            .ok_or("anchor tx has no inputs")?;
        let op = first_input.previous_output;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(op.txid.as_ref());
        OutPoint { txid, vout: op.vout }
    };
    let asset_id_bytes = wallet::hex_decode_array::<32>(&mint.asset_id)?;
    let genesis = Genesis {
        first_prev_out: commitment_genesis_point,
        tag: mint.name.clone(),
        meta_hash: [0u8; 32],
        output_index: tap_output_index,
        asset_type: if mint.amount == 1 {
            AssetType::Collectible
        } else {
            AssetType::Normal
        },
    };

    let asset = Asset::new_genesis(
        genesis.clone(),
        mint.amount,
        ScriptKey::from_pub_key(script_key),
    );

    // Build commitment proof by reconstructing the MS-SMT trees.
    print!("  Building commitment proof... ");
    io::stdout().flush().unwrap();

    let asset_id = genesis.id();
    let has_group = false;
    let ack = asset_commitment_key(&asset_id, &script_key, has_group);
    let leaf = asset_leaf(&asset);

    // Inner tree (AssetCommitment).
    let mut inner_tree = FullTree::new(DefaultStore::new());
    inner_tree
        .insert(ack, leaf.clone())
        .map_err(|e| format!("inner tree: {}", e))?;
    let inner_proof = inner_tree
        .merkle_proof(ack)
        .map_err(|e| format!("inner proof: {}", e))?;
    let inner_root = inner_tree
        .root()
        .map_err(|e| format!("inner root: {}", e))?;

    // Build AssetCommitment leaf for outer tree.
    let tap_key = tap_commitment_key(&asset_id, None);
    let ac = AssetCommitment::from_root(
        AssetVersion::V0,
        tap_key,
        genesis.asset_type,
        inner_root,
    );
    let ac_leaf = ac.tap_commitment_leaf();

    // Outer tree (TapCommitment).
    let mut outer_tree = FullTree::new(DefaultStore::new());
    outer_tree
        .insert(tap_key, ac_leaf)
        .map_err(|e| format!("outer tree: {}", e))?;
    let outer_proof = outer_tree
        .merkle_proof(tap_key)
        .map_err(|e| format!("outer proof: {}", e))?;

    let commitment_proof = CommitmentProof {
        asset_proof: Some(AssetProof {
            proof: inner_proof,
            version: AssetVersion::V0,
            tap_key,
            unknown_odd_types: std::collections::BTreeMap::new(),
        }),
        taproot_asset_proof: TaprootAssetProof {
            proof: outer_proof,
            version: TapCommitmentVersion::V2,
            unknown_odd_types: std::collections::BTreeMap::new(),
        },
        tap_sibling_preimage: None,
        stxo_proofs: std::collections::BTreeMap::new(),
        unknown_odd_types: std::collections::BTreeMap::new(),
    };
    println!("done.");

    // LOCAL VERIFICATION: Reconstruct the P2TR output and compare to on-chain.
    {
        let outer_root = outer_tree
            .root()
            .map_err(|e| format!("outer root: {}", e))?;
        let tc = TapCommitment::from_root(TapCommitmentVersion::V2, outer_root);
        let internal_x_only = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &internal_key.0[1..],
        )
        .map_err(|e| format!("x-only key: {}", e))?;

        let (expected_script, _expected_key) =
            tap_onchain::psbt::commitment::create_tap_output_script(
                &internal_x_only,
                &tc,
                None,
            )
            .map_err(|e| format!("tap output: {}", e))?;

        // Get the actual on-chain script at our output index.
        let on_chain_tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&raw_tx_for_verify)
                .map_err(|e| format!("tx parse: {}", e))?;
        let actual_script =
            &on_chain_tx.output[tap_output_index as usize].script_pubkey;

        if *actual_script == expected_script {
            println!("  P2TR output verification: MATCH");
        } else {
            println!("  P2TR output verification: MISMATCH!");
            println!(
                "    expected: {}",
                expected_script
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            println!(
                "    on-chain: {}",
                actual_script
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            return Err(
                "commitment doesn't match on-chain output -- proof would be rejected".into(),
            );
        }
    }

    // Build the full proof.
    let proof = Proof {
        version: TransitionVersion::V0,
        prev_out,
        block_header: header,
        block_height,
        anchor_tx: AnchorTx::from_bytes(&raw_tx)
            .map_err(|e| format!("anchor tx parse: {}", e))?,
        tx_merkle_proof: merkle_proof,
        asset: asset.clone(),
        inclusion_proof: TaprootProof {
            output_index: tap_output_index,
            internal_key,
            commitment_proof: Some(commitment_proof),
            tapscript_proof: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        },
        exclusion_proofs: build_exclusion_proofs(
            &raw_tx_for_verify,
            tap_output_index,
            mint.funded_psbt_hex.as_deref(),
        )?,
        split_root_proof: None,
        meta_reveal: None,
        additional_inputs: vec![],
        challenge_witness: None,
        genesis_reveal: Some(genesis),
        group_key_reveal: None,
        alt_leaves: vec![],
        unknown_odd_types: std::collections::BTreeMap::new(),
    };

    let proof_bytes = encode_proof(&proof);
    println!(
        "  Proof encoded ({} bytes, TAPP format).",
        proof_bytes.len()
    );

    // Register with universe server.
    let universe_url = "https://testnet.universe.lightning.finance";
    print!("  Registering with {}... ", universe_url);
    io::stdout().flush().unwrap();

    let client =
        tap_universe::http_client::HttpUniverseClient::new(universe_url);

    client
        .insert_proof(
            &AssetId(asset_id_bytes),
            tap_universe::types::ProofType::Issuance,
            &OutPoint { txid: tx_hash, vout: tap_output_index },
            &script_key,
            &proof_bytes,
        )
        .map_err(|e| format!("{}", e))?;

    Ok(())
}

/// Builds a Bitcoin transaction merkle proof from a list of txids.
fn build_tx_merkle_proof(
    txids: &[String],
    target_index: usize,
) -> Result<tap_primitives::proof::tx_merkle::TxMerkleProof, String> {
    use bitcoin_hashes::{sha256d, Hash, HashEngine};

    if txids.is_empty() {
        return Err("empty txid list".into());
    }

    // Convert display txids to internal byte order hashes.
    let mut hashes: Vec<[u8; 32]> = txids
        .iter()
        .map(|txid_hex| {
            let mut bytes = wallet::hex_decode_array::<32>(txid_hex)?;
            bytes.reverse(); // Display → internal.
            Ok(bytes)
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Single tx in block — empty proof.
    if hashes.len() == 1 {
        return Ok(tap_primitives::proof::tx_merkle::TxMerkleProof {
            nodes: vec![],
            bits: vec![],
        });
    }

    let mut nodes = Vec::new();
    let mut bits = Vec::new();
    let mut index = target_index;

    // Build merkle tree level by level, collecting siblings.
    while hashes.len() > 1 {
        // If odd number, duplicate the last hash.
        if hashes.len() % 2 != 0 {
            hashes.push(*hashes.last().unwrap());
        }

        // Record sibling for our target.
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        nodes.push(hashes[sibling_index]);
        bits.push(index % 2 == 0); // true = we're on the left.

        // Compute next level.
        let mut next_level = Vec::new();
        for pair in hashes.chunks(2) {
            let mut engine = sha256d::Hash::engine();
            engine.input(&pair[0]);
            engine.input(&pair[1]);
            next_level.push(sha256d::Hash::from_engine(engine).to_byte_array());
        }

        hashes = next_level;
        index /= 2;
    }

    Ok(tap_primitives::proof::tx_merkle::TxMerkleProof { nodes, bits })
}

fn cmd_list(state: &WalletState) {
    if state.assets.is_empty() && state.mints.is_empty() {
        println!("No assets. Mint something first!");
        return;
    }

    println!("Assets from mints:");
    for mint in &state.mints {
        println!(
            "  {} -- {} units (asset_id: {})",
            mint.name, mint.amount, mint.asset_id
        );
    }

    if !state.assets.is_empty() {
        println!("\nConfirmed assets:");
        for asset in &state.assets {
            println!(
                "  {} -- {} units (outpoint: {})",
                asset.asset_id, asset.amount, asset.outpoint
            );
        }
    }
}

fn cmd_receive<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    state: &mut WalletState,
    asset_id_hex: &str,
    amount_str: &str,
) where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let asset_id = match parse_asset_id(asset_id_hex) {
        Some(id) => id,
        None => {
            println!("Invalid asset ID hex (expected 64 hex chars).");
            return;
        }
    };
    let amount: u64 = match amount_str.parse() {
        Ok(a) => a,
        Err(_) => {
            println!("Invalid amount.");
            return;
        }
    };

    match node.new_address(asset_id, amount) {
        Ok(addr) => {
            let addr_str = addr.encode().unwrap_or_else(|e| format!("<error: {}>", e));
            println!("Receive address: {}", addr_str);
            state.add_address(asset_id_hex.to_string(), amount, addr_str);
            state.save();
        }
        Err(e) => println!("Failed to generate address: {}", e),
    }
}

fn cmd_send<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    state: &mut WalletState,
    asset_id_hex: &str,
    amount_str: &str,
    address: &str,
) where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let asset_id = match parse_asset_id(asset_id_hex) {
        Some(id) => id,
        None => {
            println!("Invalid asset ID hex.");
            return;
        }
    };
    let amount: u64 = match amount_str.parse() {
        Ok(a) => a,
        Err(_) => {
            println!("Invalid amount.");
            return;
        }
    };

    let recipient = match TapAddress::decode(address) {
        Ok(a) => a,
        Err(e) => {
            println!("Invalid TAP address: {}", e);
            return;
        }
    };

    println!("Sending {} units of {}...", amount, asset_id_hex);
    match node.send_asset(asset_id, amount, &recipient) {
        Ok(handle) => {
            let txid = hex_encode(&handle.txid);
            println!("Transfer broadcast! Txid: {}", txid);
            state.add_send(asset_id_hex.to_string(), amount, txid);
            state.save();
        }
        Err(e) => println!("Send failed: {}", e),
    }
}

fn cmd_sync(state: &WalletState) {
    println!("BTC balance: {} sats confirmed, {} pending",
        state.btc_confirmed, state.btc_pending);
    println!("Address: {}", state.btc_address);
    println!("Mints: {}", state.mints.len());
    println!("Assets: {}", state.assets.len());
}

// ============================================================================
// Helpers
// ============================================================================

fn print_summary(state: &WalletState) {
    println!("BTC: {} sats | Mints: {} | Assets: {}",
        state.btc_confirmed, state.mints.len(), state.assets.len());
    if state.btc_confirmed == 0 {
        println!("Fund: {}", state.btc_address);
    }
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn parse_asset_id(hex: &str) -> Option<AssetId> {
    if hex.len() != 64 {
        return None;
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(AssetId(id))
}

/// Finds the TAP commitment output index in a raw transaction.
/// The TAP output is the 330-sat P2TR output (dust limit for commitments).
/// Builds BIP-86 exclusion proofs for all P2TR outputs except the TAP output.
///
/// For each non-TAP P2TR output, we prove it doesn't contain a TAP
/// commitment by providing a TapscriptProof with Bip86=true and the
/// output's **untweaked** internal key (extracted from the funded PSBT).
fn build_exclusion_proofs(
    raw_tx: &[u8],
    tap_output_index: u32,
    funded_psbt_hex: Option<&str>,
) -> Result<Vec<tap_primitives::proof::types::TaprootProof>, String> {
    use tap_primitives::asset::SerializedKey;

    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(raw_tx)
        .map_err(|e| format!("tx parse: {}", e))?;

    // Parse the funded PSBT to get internal keys for each output.
    let psbt_internal_keys: Vec<Option<[u8; 32]>> = if let Some(hex) = funded_psbt_hex {
        let psbt_bytes = wallet::hex_decode_vec(hex)?;
        let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes)
            .map_err(|e| format!("PSBT parse: {}", e))?;
        psbt.outputs
            .iter()
            .map(|output| {
                output.tap_internal_key.map(|k| {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&k.serialize());
                    bytes
                })
            })
            .collect()
    } else {
        vec![None; tx.output.len()]
    };

    let mut exclusion_proofs = Vec::new();

    for (i, output) in tx.output.iter().enumerate() {
        if i as u32 == tap_output_index {
            continue;
        }
        if !output.script_pubkey.is_p2tr() {
            continue;
        }

        // Get the untweaked internal key from the PSBT if available.
        // For BDK outputs, this is the BIP-86 internal key before taproot tweak.
        let internal_key = if let Some(Some(x_only)) = psbt_internal_keys.get(i) {
            let mut key = [0u8; 33];
            key[0] = 0x02;
            key[1..].copy_from_slice(x_only);
            SerializedKey(key)
        } else {
            // Fallback: use the output key (won't pass verification).
            let script_bytes = output.script_pubkey.as_bytes();
            let mut key = [0u8; 33];
            key[0] = 0x02;
            key[1..].copy_from_slice(&script_bytes[2..34]);
            SerializedKey(key)
        };

        // Build TapscriptProof { Bip86: true } at TLV type 5.
        exclusion_proofs.push(tap_primitives::proof::types::TaprootProof {
            output_index: i as u32,
            internal_key,
            commitment_proof: None,
            tapscript_proof: Some(
                tap_primitives::proof::types::TapscriptProof {
                    tap_preimage_1: None,
                    tap_preimage_2: None,
                    bip86: true,
                    unknown_odd_types: std::collections::BTreeMap::new(),
                },
            ),
            unknown_odd_types: std::collections::BTreeMap::new(),
        });
    }

    Ok(exclusion_proofs)
}

fn find_tap_output_index(raw_tx: &[u8]) -> Result<u32, String> {
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(raw_tx)
        .map_err(|e| format!("tx deserialize: {}", e))?;

    // Find the 330-sat P2TR output (our TAP commitment).
    for (i, output) in tx.output.iter().enumerate() {
        if output.value.to_sat() == 330 && output.script_pubkey.is_p2tr() {
            return Ok(i as u32);
        }
    }

    // Fallback: find smallest P2TR output.
    let mut smallest = (0u32, u64::MAX);
    for (i, output) in tx.output.iter().enumerate() {
        if output.script_pubkey.is_p2tr() && output.value.to_sat() < smallest.1 {
            smallest = (i as u32, output.value.to_sat());
        }
    }
    if smallest.1 < u64::MAX {
        return Ok(smallest.0);
    }

    Err("no P2TR output found in transaction".into())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Derives a short fingerprint from the mnemonic for per-wallet directory naming.
/// Uses first 8 hex chars of SHA256(mnemonic).
fn wallet_fingerprint(mnemonic: &str) -> String {
    use bitcoin::hashes::{sha256, Hash};
    let hash = sha256::Hash::hash(mnemonic.trim().as_bytes());
    hash.to_byte_array()[..4]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}
