//! vaultsync: folder sync on iroh, iroh-docs and Automerge.
//!
//! `SPEC.md` is the design, `NOTES.md` records where the implementation had
//! to differ from it and why. The crate is a library so that the integration
//! tests can drive the same code as the `vaultsync` binary.

pub mod cli;
pub mod config;
pub mod engine;
pub mod filedoc;
pub mod node;
pub mod paths;
pub mod vault;
pub mod watcher;
