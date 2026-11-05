"""LUD-25 offline verification, and LUD-26's address-registration proof.

A SERVICE certifies each note it issues with its Lightning node identity key -
the same key it signs BOLT-11 invoices with - so a holder can confirm a note's
issuer and amount without contacting anyone. Signed via the node's own
signmessage RPC (lnd's /v1/signmessage, cln's signmessage), which wraps the
message with this prefix and double-SHA256s it before signing. That is
deliberate reuse: any tool that already verifies a Lightning node's signed
messages can verify a note, and neither backend can produce a bespoke
raw-digest scheme anyway.

    message = "LNURLcash:" || domain || ":" || amount_msat (decimal ASCII) || ":" || hex(Q)
    digest  = sha256(sha256("Lightning Signed Message:" || message))

``domain`` is the mint's lowercase hostname, the string the canonical spend
transaction commits to, so a certificate names the one mint on that domain and
never vouches for a note at another. ``Q`` is the note's taproot output key,
for every kind of note: a bearer note's ``Q`` is public too, so a SERVICE can
certify one without disclosing what spends it.

Two older messages are still read, never written, since notes people hold
carry them: ``hex(Q)`` without the domain (before luds 92abbb3), reported as
``Certification.CERTIFIED_OVER_LEGACY_Q``, and a bearer note's hash ``h`` from
before notes were keyed by ``Q``, reported as ``CERTIFIED_OVER_HASH``.

A certificate proves issuance, not that the spend in hand opens the note: a
ck1 states its ``Q`` in plain sight, so anyone who has seen a note's cp1 and
cs1 can pair them with a signature that opens nothing.
:func:`verify_note_signature` makes both checks, which is why it needs the
mint's domain.
"""

from __future__ import annotations

from enum import Enum
from hashlib import sha256

from coincurve import PrivateKey, PublicKey, PublicKeyXOnly

from . import bech32
from .errors import ProtocolError
from .note import note_declared_amount, note_k1, note_signature
from .recoverable import (
    SpendKind,
    decode_cp1,
    decode_cs1,
    decode_cs1_with_amount,
    decode_cx1,
    decode_spend,
    encode_cx1,
    note_id_of,
    verify_spend,
)
from .secrets import is_preimage
from .spend import bearer_hash_of_leaf, bearer_note_id, spend_domain_of

_LIGHTNING_SIGNED_MESSAGE_PREFIX = b"Lightning Signed Message:"
_DOMAIN_TAG = "LNURLcash"


# ---- the address-registration proof ----
#
# LUD-26: a share's own key proves the share is the registrant's.
#
#     register    sha256("LNURLcash:register:" || domain || ":" || username || ":" || cx1)
#     update      sha256("LNURLcash:update:" || domain || ":" || username || ":" || new cx1)
#     unregister  sha256("LNURLcash:unregister:" || domain || ":" || username)
#
# signed BIP-340 by the share's private key at S/a'/2/n', and verified against
# x(P) of the cx1 being registered or, for update and unregister, the one on
# file. A PUT carries an update ``sig`` by the key on file and a register
# ``newsig`` by the new share.


def address_proof_message(
    action: str, domain: str, username: str, cx1: str | None = None
) -> str:
    """The message for ``action`` (``register``, ``update`` or ``unregister``).

    ``domain`` is the SERVICE's own hostname: a URL or ``host:port`` is reduced
    to it, as for a spend (see :func:`~lnurlcash_kit.spend.spend_domain_of`).
    ``username`` is lowercased, as LUD-26 has it signed and stored. ``cx1`` is
    the share being registered, or for ``update`` the new one, and must be
    absent for ``unregister``; it is signed in its canonical lowercase
    spelling. Raises ``ProtocolError`` for anything else."""
    try:
        domain = spend_domain_of(domain)
    except ProtocolError:
        raise ProtocolError("an address proof names the SERVICE's domain") from None
    username = username.strip().lower() if isinstance(username, str) else ""
    if not username:
        raise ProtocolError("an address proof names a username")
    if action not in ("register", "update", "unregister"):
        raise ProtocolError("an address proof action is register, update or unregister")
    if cx1 is not None:
        decoded = decode_cx1(cx1)
        if decoded is None:
            raise ProtocolError("that is not a cx1")
        cx1 = encode_cx1(decoded)
    if action == "unregister":
        if cx1 is not None:
            raise ProtocolError("an unregister proof binds no cx1")
        return f"{_DOMAIN_TAG}:unregister:{domain}:{username}"
    if cx1 is None:
        raise ProtocolError(f"a {action} proof binds the cx1 it puts on file")
    return f"{_DOMAIN_TAG}:{action}:{domain}:{username}:{cx1}"


def address_proof_digest(
    action: str, domain: str, username: str, cx1: str | None = None
) -> bytes:
    """:func:`address_proof_message`, hashed to the 32-byte digest that is
    actually signed: the message is variable-length, and most Schnorr signers
    only take 32 bytes."""
    return sha256(address_proof_message(action, domain, username, cx1).encode("utf-8")).digest()


def sign_address_proof(
    share_secret_key: bytes,
    action: str,
    domain: str,
    username: str,
    cx1: str | None = None,
) -> bytes:
    """Sign an address proof as a raw 64-byte BIP-340 signature over
    :func:`address_proof_digest`, with 32 zero auxiliary bytes so a retried
    request resends the same proof. The key is the signing share's own private
    key (:func:`~lnurlcash_kit.recoverable.derive_share_node`): the share being
    registered, or for ``update`` and ``unregister`` the one on file."""
    key = bytes(share_secret_key)
    if len(key) != 32:
        raise ProtocolError("a share secret key is 32 bytes")
    try:
        signer = PrivateKey(key)
    except ValueError as err:
        raise ProtocolError("a share secret key is a scalar in [1, n)") from err
    return signer.sign_schnorr(
        address_proof_digest(action, domain, username, cx1), bytes(32)
    )


def verify_address_proof(
    signer_cx1: str,
    signature: bytes,
    action: str,
    domain: str,
    username: str,
    cx1: str | None = None,
) -> bool:
    """What a SERVICE checks: does ``signature`` (64 bytes) verify against
    ``x(P)`` of ``signer_cx1``, the cx1 being registered or the one on file,
    over this action's message? False for anything malformed. Never raises."""
    signer = decode_cx1(signer_cx1) if isinstance(signer_cx1, str) else None
    if signer is None or not isinstance(signature, (bytes, bytearray)):
        return False
    try:
        digest = address_proof_digest(action, domain, username, cx1)
        return bool(PublicKeyXOnly(signer.pubkey_x_only).verify(bytes(signature), digest))
    except Exception:
        return False


# ---- certificates ----


def _lightning_signed_digest(message: str) -> bytes:
    """What a Lightning node's signmessage puts its pen to, and so what every
    recoverable-ECDSA SERVICE signature is made over."""
    inner = sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + message.encode()).digest()
    return sha256(inner).digest()


def _require_note_id(k1: str) -> str:
    note_id = note_id_of(k1)
    if note_id is None:
        raise ProtocolError("a k1 is a ck1, a cw1, or a bearer note's 32-byte hex preimage")
    return note_id


def note_signature_message(k1: str, domain: str, amount_msat: int) -> str:
    """The message a SERVICE certifies for the note ``k1`` spends at
    ``domain`` (a note URL, a mint URL or a bare host): over ``hex(Q)``.
    Raises ``ProtocolError`` for a ``k1`` that is no spend or a ``domain``
    that names none."""
    return note_signature_message_for_hash(_require_note_id(k1), domain, amount_msat)


def note_signature_message_for_hash(note_id: str, domain: str, amount_msat: int) -> str:
    """The same message over a note id given directly, ``hex(Q)``, used exactly
    as given, lowercased: all a watcher holding only a ``cx1`` has. Raises
    ``ProtocolError`` for a ``domain`` that names none."""
    return f"{_DOMAIN_TAG}:{spend_domain_of(domain)}:{amount_msat}:{note_id.strip().lower()}"


def note_signature_digest(k1: str, domain: str, amount_msat: int) -> bytes:
    return note_signature_digest_for_hash(_require_note_id(k1), domain, amount_msat)


def note_signature_digest_for_hash(note_id: str, domain: str, amount_msat: int) -> bytes:
    return _lightning_signed_digest(note_signature_message_for_hash(note_id, domain, amount_msat))


def legacy_note_signature_message_for_hash(note_id: str, amount_msat: int) -> str:
    """The superseded message without a domain, ``LNURLcash:<amount>:<id>``,
    over ``hex(Q)`` or a bearer note's ``h``. Read, never written: a SERVICE
    MUST NOT issue it any more."""
    return f"{_DOMAIN_TAG}:{amount_msat}:{note_id.strip().lower()}"


def legacy_note_signature_digest_for_hash(note_id: str, amount_msat: int) -> bytes:
    return _lightning_signed_digest(legacy_note_signature_message_for_hash(note_id, amount_msat))


class Certification(Enum):
    """Whether a certificate verified, and over which message. Only
    ``NOT_CERTIFIED`` is falsy, so ``if verify_note_signature(...)`` reads as
    it always did."""

    #: the certificate does not verify for this note and amount
    NOT_CERTIFIED = "not certified"
    #: signed over ``hex(Q)`` at the note's domain, as LUD-25 specifies
    CERTIFIED_OVER_Q = "certified over hex(Q)"
    #: ``hex(Q)`` with no domain, as a SERVICE signed before luds 92abbb3. It
    #: still proves issuance of that note for that amount by that key, but not
    #: at which of the key's mints. A mint should re-issue ``c``
    CERTIFIED_OVER_LEGACY_Q = "certified over hex(Q) with no domain (before luds 92abbb3)"
    #: a bearer note certified over its ``h``, the message a mint used before
    #: every note was keyed by ``Q``. Genuine, but from a mint that has not
    #: caught up
    CERTIFIED_OVER_HASH = "certified over the bearer note's h (pre-taproot)"

    @property
    def verified(self) -> bool:
        return self is not Certification.NOT_CERTIFIED

    def __bool__(self) -> bool:
        return self.verified


def _is_hex_id(note_id: object) -> bool:
    return isinstance(note_id, str) and is_preimage(note_id)


def _certificate_bytes(signature: str, amount_msat: int, lenient: bool) -> bytes | None:
    """The signature bytes, from a cs1 that states ``amount_msat``, or for a
    legacy message also from a fixed-HRP cs1 or raw hex. ``lenient`` admits a
    recovery id outside 0 to 3, which only a certificate in the leading layout
    has."""
    if not isinstance(signature, str):
        return None
    trimmed = signature.strip()
    current = decode_cs1_with_amount(trimmed)
    if current is not None:
        # An amount-bearing cs1 must state the amount it signs: a payload
        # moved under another amount's prefix would otherwise verify while
        # displaying an amount nobody certified.
        return current.signature if current.amount_msat == amount_msat else None
    if not lenient:
        return None
    raw = decode_cs1(trimmed)
    if raw is None:
        decoded = bech32.decode(trimmed, constant=bech32.BECH32M)
        if decoded is not None and decoded[0].startswith("cs") and len(decoded[1]) == 65:
            raw = decoded[1]
    if raw is None:
        try:
            raw = bytes.fromhex(trimmed)
        except ValueError:
            return None
    return raw if len(raw) == 65 else None


def _recovers_to(
    digest: bytes, signature: bytes, both_layouts: bool, mint_pubkey_hex: str
) -> bool:
    """Which end of the raw bytes carries the recovery id varies by
    implementation: LUD-25 calls for ``r || s || recovery_id``, the layout raw
    BOLT-11 signatures use, while lnurl-mint once forwarded its node's
    signmessage output unreordered as ``recovery_id || r || s``. A current
    certificate is only ever the first; the legacy messages try both, which
    costs nothing security-wise - recovering against the wrong one yields an
    unrelated key that cannot match."""
    if not isinstance(mint_pubkey_hex, str):
        return False
    target = mint_pubkey_hex.strip().lower()
    layouts = [signature]
    if both_layouts:
        layouts.append(signature[1:] + signature[:1])
    for candidate in layouts:
        try:
            recovered = PublicKey.from_signature_and_message(candidate, digest, hasher=None)
        except Exception:
            # not a valid recovery under this layout - try the other
            continue
        if recovered.format(compressed=True).hex() == target:
            return True
    return False


def verify_note_signature_hash(
    note_id: str, domain: str, amount_msat: int, signature: str, mint_pubkey_hex: str
) -> bool:
    """Check a current certificate over exactly the 64-hex ``note_id`` given,
    ``hex(Q)``, at ``domain`` (a note URL, a mint URL or a bare host): what a
    watcher holding only a ``cx1`` checks a note it derived by. Prefer
    :func:`check_note_certificate` or :func:`verify_note_signature`, which work
    out the id themselves and fall back to the legacy messages.

    ``signature`` is an amount-bearing cs1, which must state ``amount_msat``
    in its human-readable part as well as sign it, with its recovery id last.
    Never raises."""
    if not _is_hex_id(note_id.strip() if isinstance(note_id, str) else note_id):
        return False
    try:
        digest = note_signature_digest_for_hash(note_id.strip(), domain, amount_msat)
    except ProtocolError:
        return False
    raw = _certificate_bytes(signature, amount_msat, lenient=False)
    return raw is not None and _recovers_to(digest, raw, False, mint_pubkey_hex)


def verify_legacy_note_signature_hash(
    note_id: str, amount_msat: int, signature: str, mint_pubkey_hex: str
) -> bool:
    """:func:`verify_note_signature_hash` for the superseded message without a
    domain, over ``hex(Q)`` or a bearer note's ``h``. ``signature`` may also be
    raw hex or a fixed-HRP cs1, in either recovery-id layout, as certificates
    were issued then. Never raises."""
    if not _is_hex_id(note_id.strip() if isinstance(note_id, str) else note_id):
        return False
    raw = _certificate_bytes(signature, amount_msat, lenient=True)
    return raw is not None and _recovers_to(
        legacy_note_signature_digest_for_hash(note_id.strip(), amount_msat),
        raw,
        True,
        mint_pubkey_hex,
    )


def _certified_over(
    output_key: str,
    bearer_hash: str | None,
    domain: str,
    amount_msat: int,
    signature: str,
    mint_pubkey: str,
) -> Certification:
    if verify_note_signature_hash(output_key, domain, amount_msat, signature, mint_pubkey):
        return Certification.CERTIFIED_OVER_Q
    if verify_legacy_note_signature_hash(output_key, amount_msat, signature, mint_pubkey):
        return Certification.CERTIFIED_OVER_LEGACY_Q
    if bearer_hash is not None and verify_legacy_note_signature_hash(
        bearer_hash, amount_msat, signature, mint_pubkey
    ):
        return Certification.CERTIFIED_OVER_HASH
    return Certification.NOT_CERTIFIED


def check_note_certificate(
    reference: str, domain: str, amount_msat: int, signature: str, mint_pubkey: str
) -> Certification:
    """Check a certificate for a note named without its spend, at ``domain``:
    a ``cp1``, or a bearer note's 64-hex ``h`` (the two things that go where a
    cp1 goes). Tries ``hex(Q)`` at the domain first, then the legacy messages:
    ``hex(Q)`` without one and, for a bearer ``h``, the pre-taproot message
    over ``h`` itself. What a watcher, or a device that discloses only ``h``,
    checks a note by. Never raises."""
    if not isinstance(reference, str):
        return Certification.NOT_CERTIFIED
    reference = reference.strip()
    bearer_hash = None
    if is_preimage(reference):
        try:
            output_key = bearer_note_id(reference)
        except ProtocolError:
            return Certification.NOT_CERTIFIED
        bearer_hash = reference.lower()
    else:
        key = decode_cp1(reference)
        if key is None:
            return Certification.NOT_CERTIFIED
        output_key = key.hex()
    return _certified_over(output_key, bearer_hash, domain, amount_msat, signature, mint_pubkey)


def verify_note_signature(
    k1: str, domain: str, amount_msat: int, signature_hex: str, mint_pubkey_hex: str
) -> Certification:
    """LUD-25's offline check of a note, as a recipient makes it: that ``k1``
    opens its note ``Q`` at ``domain`` (see
    :func:`~lnurlcash_kit.recoverable.verify_spend`), and that
    ``signature_hex`` certifies ``domain``, ``Q`` and ``amount_msat`` under
    ``mint_pubkey_hex``. Tries the current message first, then the legacy ones
    (see :class:`Certification`).

    ``domain`` is the note URL's, in any form
    :func:`~lnurlcash_kit.spend.spend_domain_of` reads; a bearer note's spend
    opens it at any domain, but a ck1 only at the one it signed for, and the
    certificate names one mint. A cw1 whose leaf this library cannot run is
    ``NOT_CERTIFIED`` here: only the mint can say whether it opens its note,
    so check the certificate alone with :func:`check_note_certificate` or
    :func:`verify_note_signature_hash` and leave the spend to the mint.

    ``signature_hex`` is an amount-bearing cs1 for the current message; the
    legacy ones also read a fixed-prefix cs1 or 65 bytes of hex, with the
    recovery id at either end.

    Never raises. Anything unverifiable is ``NOT_CERTIFIED``.
    """
    verified = verify_spend(k1, domain)
    if verified is None or verified.unevaluated:
        return Certification.NOT_CERTIFIED
    bearer_hash = None
    spend = decode_spend(k1)
    if spend is not None and spend.kind is SpendKind.SCRIPT_PATH and spend.script_path is not None:
        h = bearer_hash_of_leaf(spend.script_path.script)
        bearer_hash = h.hex() if h is not None else None
    return _certified_over(
        verified.output_key.hex(), bearer_hash, domain, amount_msat, signature_hex, mint_pubkey_hex
    )


def verify_note_url(note_url: str, mint_pubkey_hex: str) -> tuple[int | None, Certification]:
    """LUD-25's offline check on a note URL as a recipient holds it,
    ``lnurlw://mint.example/w?k1=<spend>&c=<cs1>``: the spend from ``k1``,
    the domain from the URL's own host, and the amount from the cs1, or from
    the URL's ``amount`` when the certificate is an older one that carries
    none. Returns that amount with the verdict, the amount None when there was
    none to check. A certificate proves issuance, never that the note is still
    outstanding: rotate a received note once online. Never raises."""
    if not isinstance(note_url, str):
        return None, Certification.NOT_CERTIFIED
    k1, signature = note_k1(note_url), note_signature(note_url)
    try:
        domain = spend_domain_of(note_url)
    except ProtocolError:
        return None, Certification.NOT_CERTIFIED
    if not k1 or not signature:
        return None, Certification.NOT_CERTIFIED
    certificate = decode_cs1_with_amount(signature)
    amount = certificate.amount_msat if certificate is not None else note_declared_amount(note_url)
    if amount is None:
        return None, Certification.NOT_CERTIFIED
    return amount, verify_note_signature(k1, domain, amount, signature, mint_pubkey_hex)


