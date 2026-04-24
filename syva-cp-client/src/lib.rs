//! Client library for the syva control plane.
//!
//! Used by `syva-core` (and eventually the adapters) to connect to syva-cp,
//! register as a node, subscribe to assignments, and report state back.
//!
//! This crate is a thin, typed wrapper over the tonic-generated client in
//! `syva-proto`. It does not add behavior beyond:
//!
//! - connection bootstrap
//! - typed error conversion
//! - background heartbeat task
//! - assignment stream exposed as tonic's typed stream
//!
//! It does NOT implement the reconcile loop. That belongs in the consumer.

pub mod client;
pub mod error;

pub use client::{AppliedReport, CpClient, CpClientConfig, FailedReport, NodeRegistration};
pub use error::CpClientError;
pub use syva_proto::syva_control::v1::{NodeAssignmentUpdate, ZoneAssignment};

