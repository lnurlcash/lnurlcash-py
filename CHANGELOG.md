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

**Minting is comment-bound, and the payment preimage is only settlement proof.**
The draft keyed a fresh note by the invoice's payment preimage until 31 August
2026, when that fallback was removed outright: a preimage propagates to every
node that forwarded the payment, routinely before the payer has finished
processing it, so a note keyed by one is a note all of them can spend. A WALLET
now chooses the secret itself, before any invoice exists, and hands the SERVICE
only `sha256(secret)` in a mandatory LUD-12 `comment`; a minting `payRequest`
must advertise `commentAllowed >= 64` or it cannot mint at all. `mint_invoice_request` returns the secret
on `Request.new_secrets` - persist it before paying, because the SERVICE holds
nothing that could reconstruct it.

**The mint address carries the node stats under their wire names.** lnurl-mint
advertises `nodeCapacity` in msat, so `node_capacity_msat` is a rename and is
mapped explicitly — the TypeScript sibling shipped that rename unmapped and
read `None` for every mint.

**`parse_mint_fee` refuses a component past 2^53**, which Python alone would
carry exactly. A fee has to mean the same thing in every implementation, and
the shared vectors refuse it, so accepting it here would make this the odd one
out rather than the generous one.



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
