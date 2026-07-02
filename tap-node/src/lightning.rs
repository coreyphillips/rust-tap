// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Lightning asset channel operations.
//!
//! These methods manage the asset overlay for Lightning channels. The user
//! coordinates with their LDK `ChannelManager` for the actual channel
//! lifecycle -- tap-node handles the asset-specific state.

use tap_ldk::channel::blobs::{ChannelBlob, FundedAsset};
use tap_ldk::ldk::{AssetChannelState, ChannelId, LdkChannelOps};
use tap_ldk::rfq::PriceOracle;
use tap_onchain::chain::{AssetSigner, ChainBridge, KeyRing, WalletAnchor};
use tap_primitives::asset::{AssetId, TAPROOT_ASSETS_KEY_FAMILY};

use crate::error::TapNodeError;
use crate::event::TapEvent;
use crate::node::TapNode;

/// Prepares the asset side of a new Lightning channel.
///
/// Registers asset state with the `TapChannelManager`. The user must
/// separately call `ChannelManager::create_channel()` on their LDK node.
pub(crate) fn open_asset_channel<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    channel_id: ChannelId,
    asset_id: AssetId,
    asset_amount: u64,
) -> Result<ChannelId, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let key_desc = node.keys.derive_next_key(TAPROOT_ASSETS_KEY_FAMILY)?;

    let blob = ChannelBlob {
        funded_assets: vec![FundedAsset {
            asset_id,
            amount: asset_amount,
            script_key: key_desc.pub_key,
            // The funding proof is attached once the funding flow
            // completes (see TapAssetFundingController).
            proof: None,
        }],
        decimal_display: 0,
        group_key: None,
    };

    node.tap_channel_mgr
        .register_asset_channel(channel_id, blob);

    node.event_bus.emit(TapEvent::AssetChannelOpened {
        channel_id,
        asset_id,
        capacity: asset_amount,
    });

    Ok(channel_id)
}

/// Gets the asset channel state for a given channel ID.
pub(crate) fn get_asset_channel<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    channel_id: &ChannelId,
) -> Result<AssetChannelState, TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    node.tap_channel_mgr
        .get_channel_state(channel_id)
        .ok_or(TapNodeError::Lightning("channel not found".into()))
}

/// Closes an asset channel's asset-side state.
pub(crate) fn close_asset_channel<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    channel_id: &ChannelId,
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let state = get_asset_channel(node, channel_id)?;

    let asset_id = state
        .channel_blob
        .funded_assets
        .first()
        .map(|a| a.asset_id)
        .unwrap_or(AssetId::ZERO);

    node.event_bus.emit(TapEvent::AssetChannelClosed {
        channel_id: *channel_id,
        asset_id,
    });

    Ok(())
}

/// Handles an intercepted HTLC from the user's LDK event loop.
pub(crate) fn handle_intercepted_htlc<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    intercept_id: [u8; 32],
    next_hop_scid: u64,
    next_node_id: [u8; 33],
    amt_msat: u64,
    custom_records: &[(u64, Vec<u8>)],
) -> Result<(), TapNodeError>
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    node.tap_channel_mgr
        .handle_intercepted_htlc(
            intercept_id,
            next_hop_scid,
            next_node_id,
            amt_msat,
            custom_records,
            now,
        )
        .map_err(|e| TapNodeError::Lightning(e))
}

/// Returns whether the given SCID belongs to an asset channel.
pub(crate) fn is_asset_channel<C, W, K, L, P>(
    node: &TapNode<C, W, K, L, P>,
    scid: u64,
) -> bool
where
    C: ChainBridge + Send + Sync + 'static,
    W: WalletAnchor + Send + Sync + 'static,
    K: KeyRing + AssetSigner + Send + Sync + 'static,
    L: LdkChannelOps + Send + Sync + 'static,
    P: PriceOracle + Send + Sync + 'static,
{
    node.tap_channel_mgr.is_asset_channel(scid)
}
