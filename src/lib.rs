//! Ordinary Criome trust and attestation Interface.
//!
//! `ethos/interface.ethos` is the canonical textual projection of one
//! authority-verified, role-free bootstrap Interface. Its checked Rust
//! projection carries only encoded identities. Request/reply role seating,
//! structural wire behavior, and Signal framing remain handwritten Rust until
//! the language train reaches that behavior slice.

pub mod bootstrap_manifest;
pub mod schema;

pub const CRIOME_INTERFACE_SOURCE: &str = include_str!("../ethos/interface.ethos");
pub const CRIOME_INTERFACE_RUST: &str = include_str!("schema/lib/generated.rs");
