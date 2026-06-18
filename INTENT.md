# INTENT — signal-criome

*The peer-callable wire contract for Criome's Spartan BLS authentication
and attestation substrate. Companion to `ARCHITECTURE.md` and
`Cargo.toml`. Maintenance: `primary/skills/repo-intent.md`.*

## Repo-scope only

This file carries only the intent that is FOR this `signal-criome`
contract. Workspace-shape intent stays in the primary workspace
`primary/INTENT.md`. Daemon intent stays in `criome/INTENT.md`.
Meta-only daemon operations stay in `meta-signal-criome`.

## Why this repo exists

`signal-criome` is the **peer-callable wire contract** for the `criome`
daemon. It defines the typed records that Persona components, Lojix,
Forge, ClaviFaber feeds, and peer criome daemons send across the Criome
boundary: identity registration, signature envelopes, attestations,
verification replies, archive / channel-grant / authorization
attestation, and Criome-routed authorization of exact Signal request
digests. Meta-class operations on the daemon itself (passphrase
submission, master-key operations, policy mutation, peer-routing-table
mutation, escalation-approval replies) live in `meta-signal-criome`;
runtime key custody, storage tables, actors, and sockets live in `criome`.

## Criome verifies; Persona decides

The role boundary is load-bearing. Criome verifies and records
cryptographic authority. **Persona decides and acts.** Attestations are
separate records that reference content by typed digest and purpose;
content records do not grow proof fields. The contract deliberately
avoids the name `AuthProof` — it uses specific records:
`SignatureEnvelope`, `SignedObject`, `VerificationReceipt`,
`DelegationGrant`, `ComponentRelease`, `SignedPersonaRequest`,
`SignalCallAuthorization`, and `AuthorizationGrant`.

Quorum-bearing signed surfaces carry crystallized time. Policy evidence,
adjudicator agreement facts, routed signature submissions, and authorization
grants use `StampedSignatureEnvelope`: a bare cryptographic envelope paired
with the `AttestedMoment` that places the signature in time. The root exception
is `TimeSignature` inside `AttestedMoment` itself; those bare envelopes create
the crystallized moment and therefore cannot recursively contain one.

## The channel shape

The `Criome` channel serves two classes of client — *consumers* (anyone
asking "is this allowed?" and trusting the answer) and *peer criome
daemons* (cross-criome signature solicitation for quorum policies) — plus
identity-update and authorization-observation subscribers. Requests carry
contract-local operation roots (`Sign`, `VerifyAttestation`,
`RegisterIdentity`, `AuthorizeSignalCall`, `ObserveAuthorization`, and
the rest of this contract's domain verbs); replies carry receipts,
results, and snapshots. Subscriptions close through typed domain close
operations such as `IdentitySubscriptionRetraction`.

## Wire vocabulary discipline — contract-local operation roots

Per `primary/skills/contract-repo.md` §"Public contracts use
contract-local operation verbs" and `primary/skills/component-triad.md`
§"Verbs come in three layers", the contract shape is:

This crate carries only contract-local operation roots in verb form. The
old `SignalVerb` wrappers are gone; payload enum variants are the operation
heads. Runtime command lowering and any database-action classification happen
inside the `criome` daemon, never in this contract crate and never as public
wire vocabulary.

Criome is *not* a Persona component, so the mandatory `Tap`/`Untap`
observable block does not apply; identity-update and
authorization-observation subscriptions stay as domain-specific open and
close operations.

## Constraints

- This crate carries only typed wire vocabulary, NOTA codecs, and
  round-trip witnesses. No daemon, no key custody, no storage tables,
  no actors, no sockets.
- Wire enums are closed; no `Unknown` escape hatch.
- The frame-layer dependency is `signal-frame`, not deprecated
  `signal-core`.
- Contract types derive NOTA in this crate; clients do not carry shadow
  types.

## Non-ownership

This crate does not own:

- the `criome` daemon, key custody, signing, or verification logic;
- meta-class daemon operations (those live in `meta-signal-criome`);
- Persona policy — Criome reports cryptographic facts; Persona decides
  and acts on them.

## See also

- `ARCHITECTURE.md` — channel shape, message list, and the three-layer
  migration plan.
- `../criome/ARCHITECTURE.md` §"Security model — Unix-user as boundary".
- `../meta-signal-criome/` — meta-class daemon contract.
- `primary/skills/contract-repo.md` — contract repo discipline and
  naming rules.
- `primary/skills/component-triad.md` — repo triad structure and wire
  layers.
