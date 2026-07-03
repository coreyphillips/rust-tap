// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Small tokio runtime holder for the blocking client wrappers.
//!
//! The rust-tap core is synchronous; tonic is async. Each blocking
//! client either owns a private single-worker multi-thread runtime or
//! borrows an existing runtime [`Handle`], and drives every RPC with
//! `block_on`.

use std::sync::Arc;

use tokio::runtime::{Builder, Handle, Runtime};

/// Either an owned runtime or a borrowed handle to an external one.
#[derive(Clone)]
pub(crate) enum BlockingRuntime {
    /// A private runtime owned by the client (shared so the client is
    /// `Clone`).
    Owned(Arc<Runtime>),
    /// A handle to a runtime owned by the caller. The caller must keep
    /// that runtime alive for the lifetime of the client and must not
    /// invoke the client from that runtime's own async context.
    Borrowed(Handle),
}

impl BlockingRuntime {
    /// Builds a private single-worker runtime.
    pub(crate) fn new_owned() -> std::io::Result<Self> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        Ok(BlockingRuntime::Owned(Arc::new(runtime)))
    }

    /// Wraps an external runtime handle.
    pub(crate) fn from_handle(handle: Handle) -> Self {
        BlockingRuntime::Borrowed(handle)
    }

    /// Runs a future to completion on this runtime.
    ///
    /// Must not be called from within an async context (tokio panics
    /// on nested `block_on`); use a plain thread or
    /// `tokio::task::spawn_blocking`.
    pub(crate) fn block_on<F: std::future::Future>(
        &self,
        future: F,
    ) -> F::Output {
        match self {
            BlockingRuntime::Owned(rt) => rt.block_on(future),
            BlockingRuntime::Borrowed(handle) => handle.block_on(future),
        }
    }
}
