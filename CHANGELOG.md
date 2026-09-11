# Changelog

Semantic versioning. While the LUD-25 draft is unmerged, `0.x` minor bumps may
carry breaking changes; pin an exact version.

## 0.1.0 — unreleased

### LUD-25 Part 2: notes keyed by a public key

A Part 2 note is keyed by a public key rather than a hash. The holder keeps
`sk`, discloses `pk` as `cp1`, and spends the note with `ck1`, a recoverable
signature by `sk`; the mint recovers `pk` from it. The new
`lnurlcash_kit.recoverable` carries lnurlcash-kit's TypeScript names in
snake_case.

- The four bech32m encodings: `cp1` (a note's key), `ck1` (its bearer secret),
  `cs1` (the mint's certificate) and `cx1` (a watch-only branch), with
  `encode_*`, `decode_*` and `is_*` for each. Fixed lengths and no 90-character
  limit; all-uppercase is accepted and mixed case refused. Decoders return
  `None` rather than raise.
- `bech32` gains bech32m, BIP-350's constant beside BIP-173's. LUD-01 decoding
  is unchanged, and neither accepts the other's checksum.
- `derive_note_pubkey` (watch-only) and `derive_note_secret_key`, the per-note
  key tweak. The index is any uint32. A tweak at or above n, or a zero key,
  raises rather than being reduced: use the next index.
- `sign_note_ownership` and `recover_note_ownership_pubkey`.
- `derive_cash_address_node` and `cash_node_to_cx1`. The branch is
  `m/139'/1'/d1..d4`, which is what lnurl-wallet derives, not the
  `m/139'/d1..d4` the spec text gives.
- `note_id_of(k1)`, the id a mint files either kind of note under, and
  `note_lookup_of(k1)`, what to look it up by without disclosing it. One note
  has many valid `ck1` strings, so notes compare by id.
- The wire takes both kinds. A `ck1` goes anywhere a `k1` does, and
  `resolve_note_input` accepts a note URL carrying one. A `cp1` output goes as
  `p1`/`p2` from the `*_with_hash` calls while a hash keeps `h`/`h2`;
  `mint_invoice_request_with_hash` sends one as the comment alone, and
  `build_note_info_url_by_hash` as `p`.
- `verify_note_signature` takes a `ck1` and a `cs1`.
  `verify_note_signature_hash`, `note_signature_message_for_hash` and
  `note_signature_digest_for_hash` do the same for a caller holding only the
  key, as a `cx1` watcher does. `note_signature_message` now raises
  `ProtocolError` for a k1 that is neither kind.
- `WithdrawRequestInfo` and `NoteInfoByHash` carry the response's `sig` as
  `signature`: for a Part 2 note, the mint's ready-made `cs1`.
- `derive_cash_master(seed)`, the BIP-32 master node.
- An extension, not LUD-25: `derive_nostr_cash_seed` and
  `derive_nostr_address_node`, a Part 2 branch rooted in a Nostr identity key
  (`HMAC-SHA256(key, "LNURLcash/nostr-seed")`, then the same path), as
  heartwood-esp32 derives it.
- Graded against `lnurlcash-conformance` 0.9.0's `part2.json` and
  `nostr-seed.json`: every field of every branch, note and certificate,
  including recovering each `ck1` to its key and each `cs1` to the mint's.

### Three more fields off a mint address

`mint_address_request` reads `nodeUris`, `sunsetDate` and
`outstandingNotesMsat`, which the reference mint publishes and this dropped.

- `node_uris` — every address the SERVICE's node announces. `node_uri` is the
  first of them; a node behind Tor as well as clearnet has more. `None` rather
  than an empty tuple when there are none.
- `sunset_date` — the day the SERVICE plans to close, ISO-8601. Validated with
  `date.fromisoformat` and dropped otherwise: the one thing a WALLET does with
  this is show it to a holder, and a wrong date is worse than no date.
- `outstanding_notes_msat` — what the SERVICE says it owes. `0` and `None` are
  different answers.

### Seed-recoverable note secrets, and the private lookup a restore needs

- `lnurlcash_kit.cash`: LUD-25's `m/139'` scheme. `derive_cash_root`,
  `derive_cash_domain_node`, `derive_cash_secret`, `cash_secret_at`,
  `cash_domain_indices`, `cash_node_to_hex`/`from_hex`, `derive_cash_child`
  and `CashSecretSource`. `d1..d4` are raw uint32 used exactly as they fall,
  hardened only where they land at or above 2^31; masking the top bit or
  hardening all four derives a different tree from every conforming wallet.
- `derive_note_root` / `derive_note_secret`: the pre-spec HMAC scheme, so
  notes minted under it stay findable. Not what to mint under.
- `build_note_info_url_by_hash` and `note_info_by_hash_request`: LUD-25's
  `?h=` informational GET. A restore walk queries a whole gap window of
  indices the wallet has not minted into yet, so asking by secret publishes
  exactly the secrets it is about to mint under.
- `NoteInfoByHash` is its own type rather than `WithdrawRequestInfo`: that
  type's `k1` is the bearer secret, and a conforming SERVICE has nothing to
  echo when the request never named one.
- Graded against `lnurlcash-conformance` 0.7.0's `cash-derivation.json` and
  `derivation.json`, including BIP-32's own published test vector 1.

First release. A Python implementation of LNURLcash, following the protocol
layer of dni's [lnurl-wallet](https://github.com/dni/lnurl-wallet) and checked
against the shared
[conformance vectors](https://github.com/TheCryptoDonkey/lnurlcash-conformance)
and the adversarial mock mint.

### Design notes

**Offline verification is mandatory, and this library insists on it.** LUD-25
stopped treating a note signature as optional: a SERVICE MUST publish
`mintPubkey` and MUST sign every note a rotate, split or merge mints. So
`note_info_request` refuses a `withdrawRequest` publishing no `mintPubkey`, or
one that is not a 33-byte compressed secp256k1 key, and a mutation the SERVICE
confirms without signing raises the new `UnverifiableNote`.
`Policy(require_signatures=False)` opts out.

That exception carries the fresh secrets, and the reason matters: `status` was
OK, so the mutation LANDED. The note exists at the hash the wallet disclosed
and that secret is the only key to it, so enforcing the spec must never be the
thing that strands the money.

**A spent-or-unknown refusal from a mutation carries its secrets too.** At a
SERVICE that has not implemented the replay rule below, a retried mutation is
answered as an already-spent input - so that refusal is also what a mutation
the SERVICE ALREADY applied looks like. `ServiceRejected` gained
`new_secrets`, and `new_secrets_of(err)` reads them off all three families that
can carry them. A refusal on policy grounds burned nothing and carries nothing.

**A mutation whose answer was lost is re-sent, and usually completes.** LUD-25
gained a "Retrying a mutation" section: a SERVICE MUST answer a byte-identical
rotate, split or merge with the success it already returned. Both clients
re-send - `mutation_retries`, default 1 - so a dropped connection resolves into
a completed mutation rather than an unresolved maybe.

A `Request` now says whether it is `replayable`, which only a rotate, split or
merge is. A melt never is: it carries `pr`, is paid asynchronously and has no
replay guarantee, so a second request could ask for a second payment. Only an
ambiguous failure is retried, and the same `Request` goes out each time rather
than a rebuilt one, because the replay is matched on the k1 set, `h`, `h2` and
`amount` - a regenerated secret would make the retry a different mutation, and
a second real burn.

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
