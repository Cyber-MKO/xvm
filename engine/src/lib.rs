//! Host-state engine.
//!
//! One process serves the facts of every emulated host: identity, OS, hardware,
//! network, users, software, services and the Windows registry. Base images are
//! held once and shared; each host stores only its delta. Profiles come from
//! `xvm-profile compile`, which is the single YAML parser and validator.

pub mod apply;
pub mod client;
pub mod eventlog;
pub mod evtquery;
pub mod files;
pub mod merge;
pub mod persist;
pub mod procs;
pub mod protocol;
pub mod registry;
pub mod runtime;
pub mod server;
pub mod store;
