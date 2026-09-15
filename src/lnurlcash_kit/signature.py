"""LUD-25 offline verification.

A SERVICE may sign each note it issues with its Lightning node identity key -
the same key it signs BOLT-11 invoices with - so a holder can confirm a note's
issuer and amount without contacting anyone. Signed via the node's own
signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
message with this prefix and double-SHA256s it before signing. That is
deliberate reuse: any tool that already verifies a Lightning node's signed
messages can verify a note, and neither backend can produce a bespoke
raw-digest scheme anyway.

    message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || note id
    digest  = sha256(sha256("Lightning Signed Message:" || message))

The note id is ``hex(sha256(k1))`` for a Part 1 note, and for a Part 2 note
the hex x-only public key its ck1 recovers to (see
:func:`~lnurlcash_kit.recoverable.note_id_of`), in which case the signature
arrives as a ``cs1``. Either way the signature commits to something public,
not the secret, so a holder can prove issuance - to expose a mint that will
not honour its own note - without revealing what would let anyone spend it.
"""

from __future__ import annotations

from hashlib import sha256

from coincurve import PrivateKey, PublicKey

from .errors import ProtocolError
from .recoverable import decode_any_cs1, note_id_of
from .secrets import is_preimage

_LIGHTNING_SIGNED_MESSAGE_PREFIX = b"Lightning Signed Message:"
_DOMAIN_TAG = "LNURLcash"


def address_proof_digest(action: str, username: str) -> bytes:
    """Return the digest used to prove control of an address branch's
    index-0 key. ``username`` must be the normalised value sent to the
    SERVICE."""
    if action not in ("register", "unregister"):
        raise ProtocolError("an address proof action is register or unregister")
    message = f"{_DOMAIN_TAG}:{action}:{username}".encode()
    return sha256(sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + message).digest()).digest()


def sign_address_proof(index_zero_secret_key: bytes, action: str, username: str) -> bytes:
    """Sign a register/update or unregister proof as raw
    ``r || s || recovery-id`` bytes."""
    key = bytes(index_zero_secret_key)
    if len(key) != 32:
        raise ProtocolError("an index-zero secret key is 32 bytes")
    try:
        signer = PrivateKey(key)
    except ValueError as err:
        raise ProtocolError("an index-zero secret key is a scalar in [1, n)") from err
    return signer.sign_recoverable(address_proof_digest(action, username), hasher=None)


def _require_note_id(k1: str) -> str:
    note_id = note_id_of(k1)
    if note_id is None:
        raise ProtocolError("a k1 is 32 bytes of hex or a ck1")
    return note_id


def note_signature_message(k1: str, amount_msat: int) -> str:
    """The message a SERVICE signs for this note. Raises ``ProtocolError`` for
    a k1 that is neither 32 bytes of hex nor a ck1 that recovers."""
    return note_signature_message_for_hash(_require_note_id(k1), amount_msat)


def note_signature_message_for_hash(h: str, amount_msat: int) -> str:
    """The same message when the caller has the note id rather than its
    secret: a hash, or a Part 2 note's public key as hex. What a watcher
    holding only a cx1 has for every note on the branch."""
    return f"{_DOMAIN_TAG}:{amount_msat}:{h.strip().lower()}"


def note_signature_digest(k1: str, amount_msat: int) -> bytes:
    return note_signature_digest_for_hash(_require_note_id(k1), amount_msat)


def note_signature_digest_for_hash(h: str, amount_msat: int) -> bytes:
    message = note_signature_message_for_hash(h, amount_msat).encode()
    return sha256(sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + message).digest()).digest()


def verify_note_signature(
    k1: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> bool:
    """Recover the signer's pubkey and check it against ``mint_pubkey_hex``.

    ``k1`` may be a Part 1 secret or a Part 2 ck1, and ``signature_hex`` 65
    bytes of hex, a current amount-bearing cs1, or a legacy fixed-prefix cs1.
    Callers can decode the carried amount separately when they need it. A
    ck1's note id is recovered locally, so checking a Part 2 note needs no
    network either.

    The signature is 65 bytes, but which end carries the recovery id varies by
    implementation: LUD-25 calls for ``r || s || recovery_id``, the layout raw
    BOLT-11 signatures use, while lnurl-mint once forwarded its node's
    signmessage output unreordered as ``recovery_id || r || s``. That is fixed
    upstream, but other implementations may still get it wrong.

    Trying both orderings costs nothing security-wise - recovering against the
    wrong one yields an unrelated pubkey that cannot match - and means a note
    verifies regardless of which convention issued it.

    Never raises. An unverifiable signature is a "no".
    """
    note_id = note_id_of(k1)
    if note_id is None:
        # a malformed k1 cannot be hashed or recovered - not a crash, a "no"
        return False
    return verify_note_signature_hash(note_id, amount_msat, signature_hex, mint_pubkey_hex)


def verify_note_signature_hash(
    h: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> bool:
    """:func:`verify_note_signature` for a caller holding the note id rather
    than its secret: a hash, or a Part 2 note's public key as hex.

    A watcher holding only a cx1 derives every note key on the branch but can
    never make a ck1, so this is how it checks the cs1 a mint returned for one.
    Never raises.
    """
    if not isinstance(h, str) or not is_preimage(h):
        return False
    if not isinstance(signature_hex, str) or not isinstance(mint_pubkey_hex, str):
        return False
    signature = decode_any_cs1(signature_hex)
    if signature is None:
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return False
    if len(signature) != 65:
        return False
    digest = note_signature_digest_for_hash(h, amount_msat)

    target = mint_pubkey_hex.strip().lower()
    # coincurve wants the recovery id last, which is also the wire format
    trailing = signature
    leading_moved = signature[1:] + signature[:1]
    for candidate in (trailing, leading_moved):
        try:
            recovered = PublicKey.from_signature_and_message(
                candidate, digest, hasher=None
            )
            if recovered.format(compressed=True).hex() == target:
                return True
        except Exception:
            # not a valid recovery under this ordering - try the other
            continue
    return False
