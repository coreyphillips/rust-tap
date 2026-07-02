# LDK Fork Requirements for tap-ldk

This document enumerates exactly which parts of `tap-ldk` are blocked on
changes to rust-lightning (LDK), what already exists in the fork we build
against, and what still needs to change upstream.

Fork in use (from `tap-ldk/Cargo.toml` and the workspace `Cargo.lock`):

- `lightning = { git = "https://github.com/coreyphillips/rust-lightning.git", branch = "main" }`
- Pinned revision: `704d8f950106792fe2beb4289e118507f841ee30`

All fork-state claims below were verified directly against the local
checkout of that revision (`~/.cargo/git/checkouts/rust-lightning-*/704d8f9`),
so no claim in this document requires upstream re-verification.

## The tiered integration model

`tap-ldk/src/lib.rs` defines three integration tiers:

- Tier A - works today with stock LDK APIs: custom peer messages via
  `CustomMessageHandler`, HTLC interception via `Event::HTLCIntercepted`
  and `ChannelManager::forward_intercepted_htlc`, custom TLV records in
  HTLC onion payloads, and RFQ negotiation as a standalone protocol.
- Tier B - small upstream LDK changes needed: opaque blob storage in
  channel state, `TxBuilder` extensibility for auxiliary tapscript
  leaves, and auxiliary signatures in `CommitmentSigned`.
- Tier C - significant LDK changes needed: funding output tapscript
  hooks and asset-aware on-chain resolution (cooperative close outputs,
  force-close sweeping).

The traits in `tap-ldk/src/channel/traits.rs` define the target API and
mirror lnd's auxiliary hook architecture; the file itself notes that
implementing them fully "requires upstream LDK changes (Milestone 9 PRs)".

## Interface map: lnd aux hooks vs tap-ldk traits vs LDK fork status

The Go side is `taproot-assets/tapchannel/` (files listed below). The
Rust side is `tap-ldk/src/channel/traits.rs` plus `routing` and `rfq`.

| lnd aux interface (Go file) | tap-ldk equivalent | LDK fork status | Blocking detail |
|---|---|---|---|
| `funding.AuxFundingController` (`aux_funding_controller.go`, `FundingController`) | `AssetFundingController` (traits.rs), `channel/funding.rs` | Missing (hard blocker) | Wire messages work via `CustomMessageHandler` (Tier A), but LDK has no hook to override the funding output script. Asset channels require the funding output to be a taproot output committing to a `TapCommitment` root; the fork still builds a plain 2-of-2 via `make_funding_redeemscript`. |
| Aux leaf fetching (`aux_leaf_creator.go`, `FetchLeavesFromView`; lnd's aux leaf store role) | `AssetLeafCreator` (traits.rs), `TapAssetLeafCreator` (leaf_creator.rs), `TapTxBuilder` (tap_tx_builder.rs) | Partially available | The fork adds a `TxBuilder` trait with a `get_aux_commitment_data()` hook, and `TapTxBuilder` implements it. But `ChannelManager` cannot be given a custom `TxBuilder` (see below), and nothing in the fork ever calls `get_aux_commitment_data()`. |
| `AuxLeafSigner` (`aux_leaf_signer.go`; processes `lnwallet.AuxSigJob` / `AuxVerifyJob`) | `AssetLeafSigner` (traits.rs), `TapAssetLeafSigner` (leaf_signer.rs) | Partially available | `CommitmentSigned.aux_signatures` exists in the fork but is always `None`; there is no path to populate, verify, or persist aux signatures. |
| `AuxTrafficShaper` (`aux_traffic_shaper.go`) | `AssetTrafficShaper` (traits.rs), `routing/mod.rs`, `TapChannelManager::handle_intercepted_htlc` (ldk/mod.rs) | Available (Tier A) | Works today via `Event::HTLCIntercepted` and `forward_intercepted_htlc`; no fork changes required for forwarding-time shaping. |
| `AuxChanCloser` (`aux_closer.go`) | `AssetChannelCloser::cooperative_close_outputs` (traits.rs), `TapAssetChannelCloser` (closer.rs) | Missing | No cooperative-close output hooks exist anywhere in the fork; closing negotiation cannot accept extra asset outputs. |
| `AuxSweeper` (`aux_sweeper.go`) | `AssetChannelCloser::force_close_outputs` (traits.rs), `TapAssetChannelCloser` (closer.rs) | Missing | No sweeper or chain-resolution hooks exist in the fork; asset outputs on a broadcast commitment cannot be swept with proofs. |
| Aux contract resolver (`AuxSweeper::ResolveContract` in `aux_sweeper.go`) | Folded into `AssetChannelCloser::force_close_outputs`; no dedicated trait yet | Missing | Same as above: LDK's chain monitoring / `OnchainTxHandler` has no hook to request resolution blobs for aux outputs. |
| `AuxInvoiceManager` (`aux_invoice_manager.go`, via `InvoiceHtlcModifier` and `RfqManager`) | `rfq::QuoteManager`, `TapChannelManager::handle_tap_message` and `handle_intercepted_htlc` (ldk/mod.rs) | Available (Tier A) | Receive-side amount translation is done at HTLC interception time using RFQ quotes; no fork changes required. |

Note: tap-ldk deliberately merges lnd's `AuxChanCloser`, `AuxSweeper`, and
contract-resolver roles into the single `AssetChannelCloser` trait
(traits.rs documents it as "Equivalent of LND's AuxChanCloser + AuxSweeper").

## Blocked items and the exact LDK change needed

### 1. TxBuilder cannot be injected into ChannelManager (Tier B)

Fork state (verified at rev 704d8f9):

- `lightning/src/sign/tx_builder.rs` defines the `TxBuilder` trait,
  including the aux hook `get_aux_commitment_data(&self, local,
  commitment_number, aux_data: Option<&[u8]>) -> Vec<(u32, Vec<u8>)>`
  with a default empty implementation.
- `lightning/src/ln/channel.rs` hardcodes `SpecTxBuilder {}` at every
  call site (channel stats and `build_commitment_transaction`). There is
  no generic parameter or constructor argument on `ChannelManager` (or
  on the channel structs) to install a custom `TxBuilder`.
- `get_aux_commitment_data()` is never called from `lightning/src/ln/`.

Required LDK change: `ChannelManager` (and the per-channel code paths)
must accept an injected `TxBuilder` implementation - e.g. a new generic
parameter threaded through `ChannelManager::new` - and commitment
construction must call `get_aux_commitment_data()` and embed the
returned leaves into the commitment output scripts. Until then,
`TapTxBuilder` (tap_tx_builder.rs) compiles and is unit-tested but can
never be exercised by a running node.

### 2. Aux channel/commitment blobs are inert (Tier B)

Fork state (verified at rev 704d8f9):

- `lightning/src/ln/channel.rs` has `pub(crate) aux_channel_data:
  Option<Vec<u8>>` and `pub(crate) aux_commitment_data: Option<Vec<u8>>`
  on the channel context.
- They are only ever assigned `None` at channel construction. There is
  no public setter and no code path that populates them.
- Serialization plumbing exists (odd TLV types 81 and 83 in the channel
  encode/decode paths, commented "Taproot Assets: channel blob /
  commitment blob"), but because the fields are never set they always
  round-trip as absent - the persistence path is effectively dead code.

Required LDK change: a public API to attach the channel blob at funding
time and update the commitment blob on each state transition (most
naturally fed by the injected `TxBuilder` / funding hook), so the blobs
are actually populated, persisted with the channel, and handed back to
`get_aux_commitment_data()` as its `aux_data` argument on restart.
tap-ldk currently works around this with a parallel out-of-LDK store in
`TapChannelManager` (ldk/mod.rs), which is not crash-consistent with
LDK's own channel persistence.

### 3. CommitmentSigned.aux_signatures is never populated (Tier B)

Fork state (verified at rev 704d8f9):

- `lightning/src/ln/msgs.rs` adds `pub aux_signatures:
  Option<Vec<u8>>` to `CommitmentSigned`, wired into the message TLV
  stream.
- Every construction site in the fork sets `aux_signatures: None`, and
  the receive path never validates or stores it.

Required LDK change: commitment signing must call into an aux signer
(e.g. via the injected `TxBuilder` or a companion trait) to produce the
second-level asset signatures that `TapAssetLeafSigner`
(leaf_signer.rs) already knows how to create; the receive path must
verify them and persist them with the counterparty commitment so they
are available at force-close time. Without this, an asset HTLC on a
broadcast commitment cannot be claimed at the asset level.

### 4. No funding-output override hook (Tier C - hard blocker)

Fork state (verified at rev 704d8f9): the funding output script is
always the standard 2-of-2 from `make_funding_redeemscript`; there is no
hook anywhere in the funding flow to substitute a different script.

Required LDK change: funding transaction construction (and funding
output validation on accept) must allow overriding the funding output
script with a taproot output whose tweak commits to a `TapCommitment`
root, mirroring what lnd exposes to `funding.AuxFundingController`
(`AuxFundingDesc` in `aux_funding_controller.go`). This is the single
change without which no asset channel can exist at all: everything in
tiers B and C above only matters once the funding output itself can
carry the asset commitment. The Tier A funding message exchange in
`channel/funding.rs` (proof transfer, validation, blob production) is
ready and waiting on this hook.

### 5. No cooperative-close output hooks (Tier C)

Fork state (verified at rev 704d8f9): no `AuxChanCloser`-like concept
exists; grep for aux close/sweep hooks across `lightning/src/` finds
nothing.

Required LDK change: cooperative close negotiation must accept extra
outputs (script + value + ordering constraints) supplied by an external
hook, and both sides must validate the peer's version of those outputs,
mirroring lnd's `AuxChanCloser`. `TapAssetChannelCloser::
cooperative_close_outputs` (closer.rs) already computes the required
P2TR outputs with asset commitments but has nowhere to inject them.

### 6. No sweeper / chain-resolution hooks (Tier C)

Fork state (verified at rev 704d8f9): LDK's chain monitoring and
`OnchainTxHandler` have no extension point for auxiliary outputs; there
is no equivalent of lnd's `AuxSweeper` or its `ResolveContract` API.

Required LDK change: after a force close, the chain-resolution pipeline
must expose hooks to (a) identify asset-bearing outputs on the confirmed
commitment, (b) obtain resolution/sweep data from an external component,
and (c) attach asset proof data to the sweep transaction.
`TapAssetChannelCloser::force_close_outputs` (closer.rs) produces
`SweepDescriptor`s (including CSV handling) but currently has no real
outpoints to fill in and no LDK pipeline to hand them to.

## What works today without the fork changes

Everything in Tier A runs against stock LDK APIs and is implemented and
unit-tested in this crate:

- RFQ negotiation (buy/sell request, accept, reject) over
  `CustomMessageHandler` custom messages (`wire`, `rfq`,
  `TapChannelManager::handle_tap_message`).
- Asset HTLC recognition and amount translation at forward time via
  `Event::HTLCIntercepted` custom TLV parsing and
  `forward_intercepted_htlc` (`routing`,
  `TapChannelManager::handle_intercepted_htlc`) - the LDK-side
  equivalent of lnd's `AuxTrafficShaper` and `AuxInvoiceManager`.
- The asset funding message exchange and validation logic
  (`channel/funding.rs`), short of actually creating the asset funding
  output.
- Off-LDK asset channel state tracking keyed by channel ID and SCID
  (`ldk/mod.rs`), pending native blob storage in LDK (item 2).
- All asset-level computation for the blocked hooks: leaf creation
  (leaf_creator.rs), second-level HTLC signing (leaf_signer.rs),
  commitment aux data (tap_tx_builder.rs), and close/sweep output
  construction (closer.rs). These are pure functions of the blobs and
  become live as soon as the corresponding LDK hook from the sections
  above exists.
