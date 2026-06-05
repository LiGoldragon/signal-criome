# INTENT — signal-criome

*The peer-callable wire contract for Criome's Spartan BLS authentication
and attestation substrate. Companion to `ARCHITECTURE.md` and
`Cargo.toml`. Maintenance: `primary/skills/repo-intent.md`.*

## Repo-scope only

This file carries only the intent that is FOR this `signal-criome`
contract. Workspace-shape intent stays in the primary workspace
`primary/INTENT.md`. Daemon intent stays in `criome/INTENT.md`.
Owner-only daemon operations stay in `owner-signal-criome`.

## Why this repo exists

`signal-criome` is the **peer-callable wire contract** for the `criome`
daemon. It defines the typed records that Persona components, Lojix,
Forge, ClaviFaber feeds, and peer criome daemons send across the Criome
boundary: identity registration, signature envelopes, attestations,
verification replies, archive / channel-grant / authorization
attestation, and Criome-routed authorization of exact Signal request
digests. Owner-class operations on the daemon itself (passphrase
submission, master-key operations, policy mutation, peer-routing-table
mutation, escalation-approval replies) live in `owner-signal-criome`;
runtime key custody, redb tables, actors, and sockets live in `criome`.

## Criome verifies; Persona decides

The role boundary is load-bearing. Criome verifies and records
cryptographic authority. **Persona decides and acts.** Attestations are
separate records that reference content by typed digest and purpose;
content records do not grow proof fields. The contract deliberately
avoids the name `AuthProof` — it uses specific records:
`SignatureEnvelope`, `SignedObject`, `VerificationReceipt`,
`DelegationGrant`, `ComponentRelease`, `SignedPersonaRequest`,
`SignalCallAuthorization`, and `AuthorizationGrant`.

## The channel shape

The `Criome` channel serves two classes of client — *consumers* (anyone
asking "is this allowed?" and trusting the answer) and *peer criome
daemons* (cross-criome signature solicitation for quorum policies) — plus
identity-update and authorization-observation subscribers. Requests carry
verb-form domain roots (`Sign`, `Verify`, `Register`, `Revoke`,
`Lookup`, `Authorize`, `Observe`, `Route`, `Submit`, `Reject`); replies
carry receipts, results, and snapshots. Subscriptions follow the
canonical Retract-closes-the-stream lifecycle.

## Wire vocabulary discipline — three-layer direction

Per `primary/skills/contract-repo.md` §"Public contracts use
contract-local operation verbs" and `primary/skills/component-triad.md`
§"Verbs come in three layers", the intended shape is:

- **Layer 1 (this crate):** contract-local operation roots in verb form.
  The `SignalVerb` wrappers retire; payloads become domain-named roots
  (`Verify` carries the target it verifies; `Register` carries a
  `Registration`).
- **Layer 2 (daemon):** `criome`'s own typed Command enum, lowered from
  contract operations inside the daemon — never in this contract crate.
- **Layer 3 (observation):** payloadless Sema class labels via
  `ToSemaOperation`, for cross-component introspection only.

Criome is *not* a Persona component, so the mandatory `Tap`/`Untap`
observable block does not apply; identity-update and
authorization-observation subscriptions stay as domain-specific
Subscribe/Retract pairs. The migration to this shape is in progress; the
target above is the intent.

## Constraints

- This crate carries only typed wire vocabulary, NOTA codecs, and
  round-trip witnesses. No daemon, no key custody, no redb tables, no
  actors, no sockets.
- Wire enums are closed; no `Unknown` escape hatch.
- The frame-layer dependency moves from `signal-core` to `signal-frame`
  as the migration lands.
- Contract types derive NOTA in this crate; clients do not carry shadow
  types.

## Non-ownership

This crate does not own:

- the `criome` daemon, key custody, signing, or verification logic;
- owner-class daemon operations (those live in `owner-signal-criome`);
- Persona policy — Criome reports cryptographic facts; Persona decides
  and acts on them.

## See also

- `ARCHITECTURE.md` — channel shape, message list, and the three-layer
  migration plan.
- `../criome/ARCHITECTURE.md` §"Security model — Unix-user as boundary".
- `../owner-signal-criome/` — owner-class daemon contract.
- `primary/skills/contract-repo.md` — contract repo discipline and
  naming rules.
- `primary/skills/component-triad.md` — repo triad structure and wire
  layers.
