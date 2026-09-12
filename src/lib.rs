//! Ordinary Signal contract for Criome.
//!
//! Criome is the trust component: it registers identities, admits contracts,
//! authorizes objects against them, gathers quorum signatures, proves time by
//! attested moment, and conveys root founding. Every object this contract
//! speaks of is referred to by digest, so no declaration reaches itself and
//! the whole contract fits the rkyv archive the Signal frame carries.
//!
//! `ethos/signal.ethos` is the schema authority; `build.rs` checks the
//! checked-in Rust projection in `src/generated/signal.rs` against it. The
//! portable rkyv frame, its kinds, the wire framing, and the cross-component
//! taxonomy all come from `signal` — one frame type and one taxonomy across
//! the estate, never a per-contract copy of either.

pub mod generated;
pub use generated::signal::*;

/// The portable rkyv frame and its three kinds, re-exported from `signal` so
/// a Criome frame is the same Rust type as every other contract's frame and a
/// consumer need not name `signal` itself to speak this contract.
pub use signal::{ByteViewable, Restorable, Signal, Signalizable};

/// The cross-component taxonomy this contract's types are written in,
/// re-exported from `signal` for the same reason. These are `signal`'s own
/// types, not copies of them.
pub use signal::{
    AuthorizedObjectInterest, AuthorizedObjectKind, AuthorizedObjectReference, ComponentKind,
    ComponentObjectInterest, ObjectDigest,
};

/// The authored Ethos source of this contract.
pub const ETHOS: &str = include_str!("../ethos/signal.ethos");
/// The Rust projection generated from [`ETHOS`].
pub const ETHOS_RUST: &str = include_str!("generated/signal.rs");
