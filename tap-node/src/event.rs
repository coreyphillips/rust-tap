// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Event system for tap-node notifications.

use std::sync::mpsc;

use tap_onchain::mint::BatchState;
use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};

/// Events emitted by a [`TapNode`](crate::TapNode).
#[derive(Clone, Debug)]
pub enum TapEvent {
    /// A minting batch reached a new state.
    MintBatchStateChanged {
        batch_key: SerializedKey,
        new_state: BatchState,
    },
    /// A new asset was received (proof imported and validated).
    AssetReceived {
        asset_id: AssetId,
        amount: u64,
        outpoint: OutPoint,
    },
    /// An asset transfer's anchor transaction was broadcast. The
    /// `txid` is in display byte order (as printed by explorers).
    TransferBroadcast {
        asset_id: AssetId,
        amount: u64,
        txid: [u8; 32],
    },
    /// An asset transfer was confirmed on-chain (emitted by the
    /// confirmation watcher, see [`TapNode::tick`](crate::TapNode::tick)).
    /// The `txid` is in display byte order.
    TransferConfirmed {
        asset_id: AssetId,
        amount: u64,
        txid: [u8; 32],
    },
    /// Proof was delivered to recipient via courier.
    ProofDelivered {
        asset_id: AssetId,
        recipient_script_key: SerializedKey,
    },
    /// An asset channel was opened.
    AssetChannelOpened {
        channel_id: [u8; 32],
        asset_id: AssetId,
        capacity: u64,
    },
    /// An asset channel was closed.
    AssetChannelClosed {
        channel_id: [u8; 32],
        asset_id: AssetId,
    },
    /// An asset payment was sent over Lightning.
    AssetPaymentSent {
        asset_id: AssetId,
        amount: u64,
        payment_hash: [u8; 32],
    },
    /// An asset payment was received over Lightning.
    AssetPaymentReceived {
        asset_id: AssetId,
        amount: u64,
        payment_hash: [u8; 32],
    },
    /// Universe sync completed.
    UniverseSyncCompleted { new_assets_discovered: usize },
}

/// Internal event bus using std::sync::mpsc.
pub(crate) struct EventBus {
    sender: mpsc::Sender<TapEvent>,
}

impl EventBus {
    /// Creates a new event bus, returning it and the receiver.
    pub fn new() -> (Self, mpsc::Receiver<TapEvent>) {
        let (sender, receiver) = mpsc::channel();
        (EventBus { sender }, receiver)
    }

    /// Emits an event. Silently drops if no receivers are listening.
    pub fn emit(&self, event: TapEvent) {
        let _ = self.sender.send(event);
    }
}
