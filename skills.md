# skills — signal-criome

*Per-repo agent guide for the Criome trust and attestation Signal
contract.*

## Checkpoint — read before editing

Before changing code in this repo, read:

- `~/primary/skills/contract-repo.md`
- `~/primary/skills/architecture-editor.md`
- `~/primary/skills/architectural-truth-tests.md`
- `~/primary/skills/subscription-lifecycle.md` (the canonical
  subscription FSM the identity-updates stream implements)
- `~/primary/skills/nix-discipline.md`
- this repo's `ARCHITECTURE.md`.

## What this repo is for

`signal-criome` is the Signal contract crate for Criome's Spartan
BLS authentication and attestation substrate. The crate is pure wire
vocabulary: typed records for identity registration, signature
envelopes, attestations, verification replies, archive attestation,
channel-grant attestation, authorization attestation, and
Criome-routed authorization of exact Signal request digests. One
bidirectional channel declared with `signal_channel!` in `src/lib.rs`.

Criome verifies and records cryptographic authority. Persona decides
and acts. Attestations are separate records that reference content
by typed digest and purpose; content records do not grow proof
fields.

The identity-updates subscription follows the canonical lifecycle
in `~/primary/skills/subscription-lifecycle.md`: open with
`SubscribeIdentityUpdates`, push typed `IdentityUpdate` events, close
with `IdentitySubscriptionRetraction` carrying the per-stream token,
end with a typed reply-side `SubscriptionRetracted` ack echoing the
token.

## What this repo owns

- `CriomeRequest` / `CriomeReply` (closed enums).
- `SignatureEnvelope`, `SignedObject`, `VerificationReceipt`,
  `DelegationGrant`, `ComponentRelease`, `SignedPersonaRequest`.
- `SignalCallAuthorization`, `AuthorizationGrant`,
  `AuthorizationPending`, `AuthorizationDenied`,
  `AuthorizationExpired`, `AuthorizationUnavailable`,
  `AuthorizationObservationToken`, and the signature-solicitation
  records used by the criome-daemon topology.
- `AuthorizationPolicySatisfaction` and
  `RequiredSignatureThreshold`, so grants carry the policy class,
  threshold, and satisfied signers that make the collected
  signatures sufficient.
- `AuthorizationRequestSlot` on `AuthorizationGrant`, so grants
  carry the daemon-minted durable authorization identity; consumers
  and verification paths must not derive slots from request digests.
- `AuthorizationDenial` and `AuthorizationDenialSource`, so policy
  refusal and signer refusal remain distinct on the wire.
- `AuthorizedObjectUpdateStream`, so criome can push reference-only
  authorized object pulses: digest/kind, policy contract digest,
  decision, and attested moment, never inline payload bytes.
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
- No storage or Sema tables.
- No private-key storage.
- No prompt audit or policy engine.
- No embedded proof fields in Persona content contracts.

## Load-bearing invariants

- **BLS-only signature scheme vocabulary** for Spartan Criome.
- **No `AuthProof` type.** The contract uses specific nouns
  (`SignatureEnvelope`, `Attestation`, `VerificationResult`,
  `DelegationGrant`). The `tests/round_trip.rs` source-scan witness
  asserts the absence of an `AuthProof` symbol.
- **Attestations stay out-of-band from Persona content records.**
  Content records do not grow proof fields; attestations reference
  content by typed `ObjectDigest` and `ContentPurpose`.
- **Routed authorization names exact request bytes.** Authorization
  records name the canonical Signal request digest, contract name,
  target contract operation head, scope, signature result, and
  signature set.
  Permission comes from signatures over the exact request that
  satisfy criome's policy. This contract carries the request,
  pending/granted/denied states, signature routing, policy
  satisfaction evidence, and observation vocabulary.
- **Subscription close uses both sides.** The `signal-frame` stream
  grammar binds each stream to a request-side close operation; the
  reply-side ack is the final event consumers bind to. This applies to both
  `IdentityUpdateStream` (`SubscriptionRetracted`) and
  `AuthorizationObservationStream`
  (`AuthorizationObservationRetracted`). Do not remove either close
  path.
- **Wire enums are closed.** No `Unknown` variant for lifecycle
  uncertainty. `VerificationDecision::UnknownSigner` and
  `RejectionReason::UnknownIdentity` are **positive** closed
  rejection causes ("the entity you named is not in our
  registry"), not polling-shape placeholders.
- **Every request variant is a contract-local operation in verb form.**
  The `signal_channel!` declaration is the source of truth; the
  payload's NOTA head names the contract-local operation. Round-trip tests
  assert every variant's head. Database-action classification belongs in
  the daemon, not in this public contract crate; do not add
  `AuthorizedSignalVerb`, `SemaOperation`, `ToSemaOperation`, or a
  `signal-sema` dependency here.
- **No runtime code.** No Kameo, Tokio, socket, storage, or daemon
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

## Editing patterns

### Adding a new attestation kind

1. Add the variant to `ContentPurpose` (closed enum).
2. Add the attestation record struct.
3. Add the typed reply (if it gets its own receipt shape) or reuse
   `AttestationReceipt`.
4. Add the variant to the `CriomeRequest` `signal_channel!`
   declaration as a contract-local operation in verb form (e.g.
   `Attest<Whatever>`). Daemon command lowering is implemented inside
   `criome`, not here.
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
   subscribe request, the request-side close operation, the reply-side
   ack, and the typed event variant.
4. Witness the full subscribe → event → retract → ack → end
   lifecycle.

### Adding a new routed authorization state

1. Keep signature-derived permission as the model. New authorization
   values are shaped around the exact request digest, signer identity,
   signature envelope, and requested scope.
2. Add only the state that crosses the wire: request digest, contract
   name, target contract operation head, scope, signer identity, signature
   envelope, or observation token.
3. Add the variant to `signal_channel!` as a contract-local operation in
   verb form. Authorization submission and signature facts lower to
   daemon-owned command vocabulary inside `criome`; observation and
   verification remain contract-local operation heads on the wire.
4. Add rkyv and NOTA round-trip witnesses plus a canonical example.

## NOTA codec quirk

The `signal_channel!` macro emits a request variant's NOTA head as
the **payload's record head**, not the Rust variant name. For
example, `CriomeRequest::IdentitySubscriptionRetraction(IdentitySubscriptionToken { .. })`
encodes as `(IdentitySubscriptionToken (...))`, not
`(IdentitySubscriptionRetraction ...)`. Canonical examples and
round-trip tests use the payload heads. `Identity` is the exception
with a hand-written codec; see "Load-bearing invariants" above.

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
