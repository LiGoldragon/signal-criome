# signal-criome

The ordinary Signal contract for Criome: identity registration, contract
admission, object authorization, quorum rounds, attested time, founding
conveyance, and the parked-request intercept surface.

`ethos/signal.ethos` is the schema authority. `build.rs` regenerates the
projection with `ethos-zero` and asserts it against the committed
`src/generated/signal.rs`, so the two can never drift. The crate's public
surface is that projection, re-exported from `src/lib.rs` under the names the
ethos declares.

The portable rkyv `Signal<T>` frame, the wire framing, and the cross-component
taxonomy — `ComponentKind`, `ObjectDigest`, `AuthorizedObjectReference` and
their companions — come from `signal`. They are imported, never copied: a
vendored frame is a different Rust type from every other contract's frame,
and a per-component taxonomy is not a cross-component taxonomy.

`examples/canonical.datom` holds one canonical Datom value per line. It is
written by the codec, never spelled by hand: `tests/contract.rs` rewrites it
on demand and asserts, on every run, that each line is exactly what the codec
writes for one canonical value and that each actualizes back into exactly one
of `Query` and `Response`.

The crate owns wire vocabulary. It owns no daemon, no storage, no key custody,
no policy execution, no actors, and no sockets.
