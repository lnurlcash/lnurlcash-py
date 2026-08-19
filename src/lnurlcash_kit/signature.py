"""LUD-25 offline verification.

A SERVICE may sign each note it issues with its Lightning node identity key -
the same key it signs BOLT-11 invoices with - so a holder can confirm a note's
issuer and amount without contacting anyone. Signed via the node's own
signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
message with this prefix and double-SHA256s it before signing. That is
deliberate reuse: any tool that already verifies a Lightning node's signed
messages can verify a note, and neither backend can produce a bespoke
raw-digest scheme anyway.

    message = "LNURLcash:" || amount_msat (decimal ASCII) || ":" || hex(sha256(k1))
    digest  = sha256(sha256("Lightning Signed Message:" || message))

The signature commits to the note's HASH, not its secret, so a holder can
prove issuance - to expose a mint that will not honour its own note - without
revealing what would let anyone spend it.
"""

from __future__ import annotations

from hashlib import sha256

from coincurve import PublicKey

from .secrets import hash_k1

_LIGHTNING_SIGNED_MESSAGE_PREFIX = b"Lightning Signed Message:"
_DOMAIN_TAG = "LNURLcash"


def note_signature_message(k1: str, amount_msat: int) -> str:
    return f"{_DOMAIN_TAG}:{amount_msat}:{hash_k1(k1)}"


def note_signature_digest(k1: str, amount_msat: int) -> bytes:
    message = note_signature_message(k1, amount_msat).encode()
    return sha256(sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + message).digest()).digest()


def verify_note_signature(
    k1: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> bool:
    """Recover the signer's pubkey and check it against ``mint_pubkey_hex``.

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
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(signature) != 65:
        return False
    try:
        digest = note_signature_digest(k1, amount_msat)
    except ValueError:
        # a malformed k1 (non-hex) cannot be hashed - not a crash, a "no"
        return False

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
