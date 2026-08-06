# signal-criome

The ordinary Signal Interface for Criome trust, attestation, and
authorization traffic.

The ethos/interface.ethos file is the sole human-readable structural authority.
The build verifies that authority-sealed Interface and its checked-in,
encoded-name Rust projection. Handwritten Rust supplies only behavior the
bootstrap language does not yet express: structural codecs, ordinary
request/reply seating, and the allocated Signal frame boundary.

The crate owns wire vocabulary, not the Criome daemon, storage, key custody,
policy execution, actors, sockets, or an operating-system substrate.

The Rust API intentionally exposes encoded identities. Human and agent readers
meet the vocabulary through Ethos and Dotos; no second readable Rust schema is
maintained.
