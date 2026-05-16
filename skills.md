# skills — signal-criome

*Per-repo agent guide for the Criome trust and attestation Signal
contract.*

---

## Checkpoint — read before editing

Before changing code in this repo, read:

- `~/primary/skills/contract-repo.md`
- `~/primary/skills/architecture-editor.md`
- `~/primary/skills/architectural-truth-tests.md`
- `~/primary/skills/subscription-lifecycle.md` (the canonical
  subscription FSM the identity-updates stream implements)
- `~/primary/skills/nix-discipline.md`
- this repo's `ARCHITECTURE.md`.

---

## What this repo is for

`signal-criome` is the Signal contract crate for Criome's Spartan
BLS authentication and attestation substrate. The crate is pure wire
vocabulary: typed records for identity registration, signature
envelopes, attestations, verification replies, archive attestation,
channel-grant attestation, and authorization attestation. One
bidirectional channel declared with `signal_channel!` in
`src/lib.rs`.

Criome verifies and records cryptographic authority. Persona decides
and acts. Attestations are separate records that reference content
by typed digest and purpose; content records do not grow proof
fields.

The identity-updates subscription follows the canonical lifecycle
in `~/primary/skills/subscription-lifecycle.md`: open with a typed
`Subscribe`, push typed `IdentityUpdate` events, close with a typed
request-side `Retract IdentitySubscriptionRetraction` carrying the
per-stream token, end with a typed reply-side `SubscriptionRetracted`
ack echoing the token.

---

## What this repo owns

- `CriomeRequest` / `CriomeReply` (closed enums).
- `SignatureEnvelope`, `SignedObject`, `VerificationReceipt`,
  `DelegationGrant`, `ComponentRelease`, `SignedPersonaRequest`.
- `Identity` (closed enum: `Persona`, `Agent`, `Host`, `Developer`,
  `Cluster`).
- `IdentitySubscriptionToken` and `SubscriptionRetracted`
  (per-stream identity and reply ack).
- `VerificationDecision`, `RejectionReason`, `ContentPurpose`
  (closed enums; the `Unknown*` variants name **positive** "entity
  not in our registry" rejections).

## What this repo does not own

- No daemon.
- No actor runtime.
- No socket or CLI.
- No redb or Sema tables.
- No private-key storage.
- No prompt audit or policy engine.
- No embedded proof fields in Persona content contracts.

---

## Load-bearing invariants

- **BLS-only signature scheme vocabulary** for Spartan Criome.
- **No `AuthProof` type.** The contract uses specific nouns
  (`SignatureEnvelope`, `Attestation`, `VerificationResult`,
  `DelegationGrant`). The `tests/round_trip.rs` source-scan witness
  asserts the absence of an `AuthProof` symbol.
- **Attestations stay out-of-band from Persona content records.**
  Content records do not grow proof fields; attestations reference
  content by typed `ObjectDigest` and `ContentPurpose`.
- **Subscription close uses both sides.** The kernel grammar at
  `signal-core/macros/src/validate.rs:303–331` requires the
  `stream` block to name a request-side `Retract` variant; the
  reply-side `CriomeReply::SubscriptionRetracted` ack is the final
  event consumers bind to. Both are present in `src/lib.rs`. Do
  not remove either.
- **Wire enums are closed.** No `Unknown` variant for lifecycle
  uncertainty. `VerificationDecision::UnknownSigner` and
  `RejectionReason::UnknownIdentity` are **positive** closed
  rejection causes ("the entity you named is not in our
  registry"), not polling-shape placeholders.
- **Every request variant declares a Signal root verb.** The
  `signal_channel!` declaration is the source of truth; the macro
  generates `CriomeRequest::signal_verb()` and round-trip tests
  assert every variant.
- **No runtime code.** No Kameo, Tokio, socket, redb, or daemon
  glue in this crate. The `tests/round_trip.rs` source-scan
  witness asserts absence of runtime imports.
- **Round trips cover every variant.** rkyv length-prefixed frame
  round trips in `tests/round_trip.rs`; canonical NOTA examples in
  `examples/canonical.nota` with a parser test.
- **`Identity` has a hand-written NOTA codec.** The text head IS
  the typed payload (`Persona "name"`, `Agent "name"`, …), not a
  wrapper. When adding an identity kind, add the head-dispatch arm
  in `NotaDecode for Identity` and the matching encode arm.
- **Pin upstream contracts via a named API reference.** Cargo deps
  declare `git = "..."` with a named branch/bookmark, never raw
  `rev = "..."`.

---

## Editing patterns

### Adding a new attestation kind

1. Add the variant to `ContentPurpose` (closed enum).
2. Add the attestation record struct.
3. Add the typed reply (if it gets its own receipt shape) or reuse
   `AttestationReceipt`.
4. Add the variant to the `CriomeRequest` `signal_channel!`
   declaration with `Assert` as the root verb (attestations record
   new typed facts).
5. Add the round-trip witnesses through rkyv and NOTA.
6. Update `ARCHITECTURE.md`.

### Adding a new identity kind

1. Add the variant to `Identity`.
2. Extend the `Identity` NOTA codec with the new head and matching
   encode arm.
3. Add round-trip witnesses.
4. Update consumers' identity dispatch.

### Adding a new subscription kind

1. Read `~/primary/skills/subscription-lifecycle.md` end-to-end.
2. Add the typed subscribe payload, token, snapshot, and event
   records.
3. Add the new `stream` block in `signal_channel!`, with the
   subscribe request, the request-side retract variant, the
   reply-side ack, and the typed event variant. The kernel grammar
   enforces the close-is-Retract shape.
4. Witness the full subscribe → event → retract → ack → end
   lifecycle.

---

## NOTA codec quirk

The `signal_channel!` macro emits a request variant's NOTA head as
the **payload's record head**, not the Rust variant name. For
example, `CriomeRequest::IdentitySubscriptionRetraction(IdentitySubscriptionToken { .. })`
encodes as `(IdentitySubscriptionToken (...))`, not
`(IdentitySubscriptionRetraction ...)`. Canonical examples and
round-trip tests use the payload heads. `Identity` is the exception
with a hand-written codec; see "Load-bearing invariants" above.

---

## See also

- this workspace's `skills/contract-repo.md`.
- this workspace's `skills/subscription-lifecycle.md`.
- this workspace's `skills/architectural-truth-tests.md`.
- this workspace's `ESSENCE.md` §"Perfect specificity at
  boundaries" — the rule the closed-enum discipline implements.
- `signal-persona-system`'s `skills.md`,
  `signal-persona-harness`'s `skills.md`, and
  `signal-persona-terminal`'s `skills.md` — sibling contracts
  using the same Path A subscription discipline.
