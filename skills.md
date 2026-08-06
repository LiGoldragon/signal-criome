# Working in signal-criome

Read ARCHITECTURE.md before editing.

## Structural law

- ethos/interface.ethos is the sole human-readable structural authority.
- Authority and declaration identity come only from explicit minted seats in
  src/bootstrap_manifest.rs.
- Never derive identity or canonical order from spelling, source position, or
  content hashes.
- Never add a legacy schema source, readable generated Rust type layer, or
  readable aliases for encoded generated types.
- Do not hand-edit src/schema/lib/generated.rs. Update the Ethos source and run
  the artifact update mode once, then verify ordinary builds are fresh.
- Handwritten Rust in behavior.rs may supply only behavior the current bootstrap
  language cannot express.

## Domain law

- Wire enums are closed; do not add an Unknown compatibility bucket.
- Authorization names exact content/request digests and typed signature facts.
- Attestations reference content instead of adding proof fields to content.
- Keep ordinary and meta authority separate. Passphrases, key rotation, policy
  mutation, peer-route mutation, and escalation approval belong to
  meta-signal-criome.
- Keep daemon, storage, actors, sockets, private keys, and policy execution out
  of this repository.

## Change sequence

1. Make the structural change in ethos/interface.ethos.
2. Mint explicit new declaration or variant seats only for genuinely new
   identities; preserve existing seats and canonical order.
3. Run SIGNAL_CRIOME_UPDATE_INTERFACE_ARTIFACTS=1 cargo check --lib.
4. Change encoded-name handwritten behavior only where the new shape requires
   it.
5. Update Interface, frame, Dotos, and dependency-boundary witnesses.
6. Run formatting, default and all-feature tests, clippy with denied warnings,
   rustdoc with denied warnings, and nix flake check.

Exact Git pins are intentional. Publish a corrected producer before changing a
consumer pin.
