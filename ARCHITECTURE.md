# signal-criome architecture

## Center

This repository owns the ordinary Criome Interface: the structural language
shared by clients, peer Criome instances, agents, harnesses, and GUIs when they
exchange trust, attestation, founding, quorum, and authorization facts.

The Interface is not modeled as a Rust API with a serialization format attached.
Its authority is language-independent. Rust is one checked bootstrap projection
and may disappear without changing the Interface's identity.

Beauty, elegant logic, and extension without duplication govern this boundary.
There is one structural authority and one ordinary role seating; convenient
parallel schemas are forbidden.

## Authority and projection

The ethos/interface.ethos file is the sole textual structural source. It is a
strict, role-free Interface version 1.0.0 transaction. Its checked-in Rust
binding contains the encoded authority vocabulary, declaration, variant, and
canonical-order seats. Spelling, file position, and content hashes never mint
identity.

The binding contains encoded identifiers only. There is no second structural
source, parser, readable type layer, or readable Rust alias layer.

## Current bootstrap boundary

The src/schema/lib/behavior.rs file is deliberately handwritten. It adds only
behavior not yet expressible in the strict Interface:

- structural WireShape conversion used by rkyv;
- Dotos encoding and decoding behind the dotos-text feature;
- ordinary CriomeRequest and CriomeReply role seating;
- Signal frame routing under allocated contract ID 3, wire revision 2.

The handwritten behavior names encoded Rust types directly. When the
language train acquires these behavior forms, this file should shrink or vanish;
the structural Interface must not change merely because a bootstrap substrate
does.

## Domain boundary

The request and reply roots cover:

- identity registration, lookup, revocation, and observation;
- signatures, attestations, and verification;
- exact-request authorization and its pending, granted, denied, expired, and
  unavailable states;
- authorization and authorized-object observation;
- contract admission, time checks, founding, and two-phase quorum gathering;
- parked authorizations and cross-Criome signature routing.

Wire enums are closed. Names such as UnknownSigner and UnknownIdentity are
positive domain rejections, not extension escape hatches. Authorization
facts name the exact object or request digest and the signatures that satisfy a
policy. Proof is referenced; content records do not absorb proof fields.

The repository does not own daemon execution, persistence, private keys, policy
evaluation, actor runtimes, sockets, CLI/TUI behavior, or meta-authority
operations. The latter belong on meta-signal-criome.

## Dependency boundary

The default runtime dependency graph contains only ordinary framing and
structural runtime support. Dotos is the sole optional text projection and
enters only through dotos-text.

Imported Interfaces and this producer share `signal-standard`'s one structural
wire carrier. No contract-private carrier or conversion shadow exists at an
import boundary.

All Git dependencies are pinned to exact reviewed producer commits. A corrected
producer is published before a consumer changes its pin.

## Evidence

- tests/interface_contract.rs proves the strict Interface is the sole
  structural authority and the Rust binding contains no readable root names.
- tests/frame.rs proves encoded request values retain their ordinary route and
  round-trip through the allocated frame binding.
- tests/round_trip.rs proves Dotos retains the human operation head while Rust
  remains encoded.
- tests/dependency_boundary.rs proves retired infrastructure stays out of the
  runtime graph.

Any structural change updates the Ethos transaction, mints new explicit seats
where identity is genuinely new, updates the checked-in binding and behavior
only when necessary, and renews all four witnesses.
