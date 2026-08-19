# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

First release. A Python implementation of LNURLcash, following the protocol
layer of dni's [lnurl-wallet](https://github.com/dni/lnurl-wallet) and checked
against the shared
[conformance vectors](https://github.com/TheCryptoDonkey/lnurlcash-conformance)
and the adversarial mock mint.

### Design notes

**The protocol has no I/O in it.** `lnurlcash_kit.protocol` describes each
operation as a `Request` — a URL, a parser, and the fresh secrets that must
survive a lost answer. The sync and async clients do nothing but perform the
GET, which is why they cannot drift apart, and why a caller with its own HTTP
stack can skip them entirely.

**`gross_up_for_mint_fee` is a binary search**, not an estimate-then-walk. At a
99.9999% fee a one-msat walk is around a million steps, so any guard on it
returns a non-minimal answer — and the fee is chosen by the service, so that
input is reachable on purpose.

**The proportional fee term is computed split**, as
`(g // 1e6) * ppm + ((g % 1e6) * ppm) // 1e6`. Python integers are arbitrary
precision so this changes nothing here; it is written this way deliberately so
that the Rust and Go ports, where a direct multiply overflows 64-bit unsigned
at realistic amounts, are doing visibly the same arithmetic.

**A service's `reason` is carried through exactly as sent**, empty string
included. Substituting a friendly default before classification would be read
back as though the service had said it: "Unknown service error" matches the
rule for an unknown note, and would report one on no evidence at all.

**bech32 is vendored** from the BIP-173 reference implementation rather than
taken as a dependency: sixty lines of checksum arithmetic with no crypto in
it, and a bearer-money library is better off with one fewer supply-chain edge.
