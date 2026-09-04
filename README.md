# lnurlcash-kit (Python)

LNURLcash ([LUD-25 draft](https://github.com/lnurl/luds/pull/301)) bearer
notes for Python: mint, rotate, split, merge, melt, and verify a note offline.

```bash
pip install lnurlcash-kit
```

This is an early `0.x` release tracking a **draft** spec. Pin an exact
version.

## What a bearer note is

An ordinary [LUD-03](https://github.com/lnurl/luds/blob/luds/03.md)
withdrawRequest link whose `k1` **is** the asset:

```
lnurlw://mint.example/w?k1=<secret>&amount=<msat>
```

Whoever knows the `k1` controls the sats behind it, like a banknote. The
`amount` alongside it is only a claim by whoever encoded the note; the
authoritative value is always `maxWithdrawable` from an informational GET.

## Usage

```python
from lnurlcash_kit import LnurlcashClient, resolve_note_input, verify_note_signature

client = LnurlcashClient()

url = resolve_note_input(scanned)          # bech32, lnurlw://, or https
if url is None:
    raise ValueError("not a note")

info = client.fetch_note_info(url)         # what is it actually worth?
print(info.max_withdrawable, "msat")

fresh = client.rotate_note(info.callback, info.k1)   # that GET exposed the secret

# check it, without asking anyone. Both are guaranteed: LUD-25 requires the
# mint to publish mint_pubkey and to sign what it mints, and this library
# refuses a mint that does neither.
verify_note_signature(fresh.k1, info.max_withdrawable, fresh.signature, info.mint_pubkey)
```

`AsyncLnurlcashClient` has the identical surface with `await`. Both accept
`timeout`, `offline`, `rng`, and an existing `httpx` client:

```python
async with httpx.AsyncClient() as http:
    client = AsyncLnurlcashClient(client=http, timeout=10.0)
    info = await client.fetch_note_info(url)
```

### Bring your own HTTP stack

Everything about the protocol lives in `lnurlcash_kit.protocol`, with no I/O
in it. Each operation is a `Request`: a URL to GET, a parser, and the fresh
secrets that must survive if the answer is lost.

```python
from lnurlcash_kit import protocol

req = protocol.rotate_request(callback, k1)
body = your_http_get(req.url)              # aiohttp, requests, anything
try:
    result = req.parse(body)
except AmbiguousMint:
    save(req.new_secrets)                  # first. always.
```

That is also why the sync and async clients cannot disagree about what a
response means: neither of them decides.

## The five things that will cost you money

**1. Never let the service generate a replacement secret.** On rotate, split
and merge the *wallet* draws a fresh 32 bytes and discloses only
`sha256(secret)` as `h`. A service-issued replacement has, structurally, been
seen by that service — so a "rotate" that accepts one closes no exposure at
all. This library generates them and ignores any `k1` a non-compliant service
hands back.

**2. A failed mutation is not a failure.** If a rotate times out, the service
may already have burned your input and minted the output, and the fresh
secret in your process is the only copy of that money in existence.

```python
try:
    result = client.rotate_note(callback, k1)
except AmbiguousMutation as err:
    save(err.new_secrets)                       # first. always.
    fate = client.probe_burned_note(note_url)
    # 'live'    -> nothing landed, the saved secrets are worthless
    # 'gone'    -> the burn landed, the saved secrets ARE the note
    # 'unknown' -> keep everything and try again later
```

`RequestRefused` is the opposite and safe: nothing left the process.

**3. A retried mutation is now a replay, not a double spend.** Every mutation
is a GET, HTTP treats GET as idempotent, and an LNURLcash mutation is not — the
first attempt burns the input. For most of this draft's life that was the
sharpest edge in the protocol: a stack that resent a dropped GET got "already
spent" for the second attempt, which reads as a *definitive* rejection, so the
fresh secret got discarded along with the note the service had just minted. The
hazard broke the [Kotlin](https://github.com/TheCryptoDonkey/lnurlcash-kotlin)
and [Go](https://github.com/TheCryptoDonkey/lnurlcash-go) siblings during
development, by two different mechanisms.

LUD-25 closed it. A service MUST answer a byte-identical rotate, split or merge
with the success it already returned, signature and all. So this library
re-sends one whose answer was lost, and an unstoppable transport retry is now
simply invisible:

```python
# the connection dropped after the mint applied this. It completes anyway.
fresh = client.rotate_note(callback, old_k1)
```

`mutation_retries` sets how many times (default 1; `0` restores the old
give-up-at-once behaviour). Only rotate, split and merge are re-sent — never a
melt, which carries `pr`, is paid asynchronously and has no replay guarantee —
and only an ambiguous failure, never a refusal the service actually considered.
The re-sent request is byte-identical, because the replay is matched on the k1
set, `h`, `h2` and `amount`.

`httpx` does not retry by default, which is still what this library wants: a
deliberate retry it counts is a different thing from an invisible one it does
not. If you pass your own client, do not configure a retrying transport.

**3b. Offline verification is mandatory.** A service MUST publish `mintPubkey`
and MUST sign every note a rotate, split or merge mints. `fetch_note_info`
raises `ProtocolError` for a `withdrawRequest` publishing no valid one, and a
mutation the service confirms but does not sign raises `UnverifiableNote` —
which **carries the fresh secrets**, because the mutation landed and the note
it minted is real. Read them with `new_secrets_of` and persist them before
anything else. Pass `policy=Policy(require_signatures=False)` to deal with a
mint that predates the requirement.

**4. A melt's `OK` means "in flight", not "spent".** The service pays
asynchronously and only burns the note once the payment settles, restoring it
if the payment fails. A failed melt is never reported back through the
callback — it is only observable as the note becoming spendable again. Other
operations on that `k1` raise `NotePending` meanwhile; retry, never read it as
spent.

**5. Rotate the instant you claim a minted note.** The preimage that mints a
note is generated by the service, and if it serves
[LUD-21](https://github.com/lnurl/luds/blob/luds/21.md) `verify`, *anyone* who
saw the unpaid invoice can poll for it — the payment hash travels inside the
invoice. First rotater wins.

## Seed-recoverable note secrets

LUD-25 specifies them, and this library implements the specified scheme:

```
cashHashingKey   = m/139'/0
(d1, d2, d3, d4) = HMAC-SHA256(cashHashingKey, host)[0..16] as 4 uint32
k1_i             = m/139'/d1/d2/d3/d4/i'
```

`d1..d4` are used **exactly as they fall**. BIP-32 reads any index `>= 2^31`
as hardened, so which of the four levels are hardened is decided by the mint's
own host name. Masking the top bit, or hardening all four, derives a different
tree and restores nothing, silently. Only `i` is always hardened.

```python
root = derive_cash_root(seed)                  # m/139'
source = CashSecretSource(root, host, counter)
k1 = source()                                  # hand to a mutation
save(host, source.next_index)                  # BEFORE the hash goes out
```

`derive_cash_domain_node` is its own step for a reason: every unhardened level
sits at or above it, so a hardware signer provisioned with that node rather
than the seed needs **no elliptic curve at all**. The cost is that whoever
derives it can derive every note secret held at that mint - provisioning
material, one mint's subtree, not the wallet.

`derive_note_root` / `derive_note_secret` are the pre-spec HMAC scheme this
project shipped before the draft had one. Not deprecated, because notes minted
under it are still money; just not what to mint under.

**The counter is half the backup.** A SERVICE must answer a hash lookup for a
burned note exactly as it answers one for a note it never issued, and a rotate
burns the index below, so a wallet that has rotated more than its gap limit
cannot find its own position by scanning. The per-host counter is not secret -
an index reveals nothing without the root - so back it up, and merge it
upwards only. `note_info_by_hash_request` is the private lookup a walk should
use; asking by secret publishes the very indices the wallet is about to mint
under.

## Errors

| Class | Means |
| --- | --- |
| `RequestRefused` | nothing was sent. The note is untouched. |
| `ServiceRejected` | processed and refused. Definitive. |
| `NotePending` | a melt is in flight on this `k1`. Retry. |
| `NoteSpent` | authoritative: already burned. |
| `NoteUnknown` | the service does not recognise it. |
| `AmbiguousMint` | outcome **unknown**. Assume nothing. |
| `AmbiguousMutation` | as above, carrying `.new_secrets`. |
| `UnverifiableNote` | the mutation **landed** and came back unsigned. The note is real; carries `.new_secrets`. |
| `ProtocolError` | a non-mutating response did not match the spec, including a `withdrawRequest` with no `mintPubkey`. |

Branch on the class, never on the message.

`new_secrets_of(err)` reads the fresh secrets off any exception that could
describe a mutation the service applied: ambiguous, unverifiable, or a
spent-or-unknown refusal. A refusal on policy grounds burned nothing and
carries nothing.

## Scope

This library speaks the protocol. It does not store notes, hold keys, manage
a balance, pay invoices, or run a mint. Storage and key management are yours,
and they are where most of the remaining risk lives — see
[THREAT-MODEL.md](THREAT-MODEL.md).

Amounts are integers in **milli-satoshis**, everywhere, with no exceptions.

## Provenance

The reference implementations, both dni's, both MIT:

- [lnurl-mint](https://github.com/dni/lnurl-mint) — the reference service
- [lnurl-wallet](https://github.com/dni/lnurl-wallet) — the reference wallet

This library is a Python implementation of the same protocol, following that
wallet's protocol layer and checked against the same
[conformance vectors](https://github.com/TheCryptoDonkey/lnurlcash-conformance)
as its TypeScript, Rust and Go siblings — and against the same adversarial
mock mint, which can be told to drop a connection mid-mutation, sign in the
wrong byte order, lie about a note's value, or never settle a melt.

The wider ecosystem — wallets, mints, hardware and hosted services — is
indexed in [awesome-lnurlcash](https://github.com/TheCryptoDonkey/awesome-lnurlcash).

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

The suite needs `node` and a checkout of `lnurlcash-conformance` alongside
this repo (or `LNURLCASH_CONFORMANCE` pointing at one).

## License

MIT.
