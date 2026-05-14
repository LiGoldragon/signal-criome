# ARCHITECTURE - signal-criome

`signal-criome` is the Signal contract crate for Criome's Spartan BLS
authentication and attestation substrate.

The crate is pure wire vocabulary. It defines typed records for identity
registration, signature envelopes, attestations, verification replies,
archive attestation, channel-grant attestation, and authorization attestation.
It does not own the Criome daemon, key custody, redb tables, actors, sockets,
or deployment bootstrap.

## Channel

The whole contract is one `signal_channel!` invocation in `src/lib.rs`.

| Side | Component |
|---|---|
| Request side | Persona, Lojix, Forge, ClaviFaber feeds, or future Criome clients |
| Reply side | `criome` daemon |

## Boundaries

Criome verifies and records cryptographic authority. Persona decides and acts.
Attestations are separate records that reference content by typed digest and
purpose. Content records do not grow proof fields.

`signal-criome` deliberately avoids the name `AuthProof`. The contract uses
specific records: `SignatureEnvelope`, `SignedObject`, `VerificationReceipt`,
`DelegationGrant`, `ComponentRelease`, and `SignedPersonaRequest`.

## Requests And Replies

```text
CriomeRequest                    CriomeReply
├─ Sign                           ├─ SignReceipt
├─ VerifyAttestation              ├─ VerificationResult
├─ RegisterIdentity               ├─ IdentityReceipt
├─ RevokeIdentity                 ├─ IdentitySnapshot
├─ LookupIdentity                 ├─ AttestationReceipt
├─ AttestArchive                  ├─ IdentityUpdate
├─ AttestChannelGrant             └─ Rejection
├─ AttestAuthorization
└─ SubscribeIdentityUpdates
```

Closed enums only. No `Unknown` variant and no string-tagged dispatch.

### Signal Root Verbs

Every `CriomeRequest` variant declares its root verb in the `signal_channel!`
declaration. `signal-core` generates `CriomeRequest::signal_verb()` and
`CriomeRequest::into_signal_request()` from that declaration.

```text
Sign                       -> Assert
VerifyAttestation          -> Validate
RegisterIdentity           -> Assert
RevokeIdentity             -> Retract
LookupIdentity             -> Match
AttestArchive              -> Assert
AttestChannelGrant         -> Assert
AttestAuthorization        -> Assert
SubscribeIdentityUpdates   -> Subscribe
```

## Domain Separation

Every signed payload binds an `ObjectDigest` to a `ContentPurpose`,
`Identity`, `AuditContext`, and optional expiry. Detached signatures over raw
bytes are not modeled by this contract.

## Bootstrap Convention

Consumers discover Criome's root public key at `/etc/criome/root.pub` in
deployed systems. Test runners may override that path with an explicit
environment variable, but the contract's vocabulary treats the root key as a
registered public key, not as a hard-coded global.

## Non-Ownership

- No daemon.
- No actor runtime.
- No socket or CLI.
- No redb or Sema tables.
- No private-key storage.
- No prompt audit or policy engine.
- No embedded proof fields in Persona content contracts.

## Tests

`tests/round_trip.rs` covers:

- per-variant frame round trips for every request and reply variant;
- representative NOTA text round trips for request and reply roots;
- BLS-only signature scheme vocabulary;
- no `AuthProof` naming;
- no runtime, daemon, or storage dependencies in the contract crate.

## See Also

- `~/primary/skills/contract-repo.md`
- `../signal-core/ARCHITECTURE.md`
