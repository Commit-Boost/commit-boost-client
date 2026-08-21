//! cb-km-tool: reference keymanager builder_config projector for Commit-Boost
//! mux configs (keymanager-APIs #88). Library-first: `project` turns a CB
//! config + operational overlay into per-key KM docs; `apply` POSTs them to
//! validator clients; `check` compares stored docs canonically.

pub mod doc;
pub mod overlay;

pub use doc::{BuilderConfigDoc, BuilderEntryDoc, CanonicalDoc};
pub use overlay::Overlay;
