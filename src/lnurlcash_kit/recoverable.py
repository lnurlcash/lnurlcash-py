"""LUD-25 Part 2: notes keyed by a public key and spent by a recoverable
signature.

A Part 2 note is keyed by a public key rather than a hash. The holder keeps
``sk``, discloses ``pk`` as ``cp1<pk>``, and spends the note with ``ck1``, a
recoverable signature by ``sk`` over a fixed message: the SERVICE recovers
``pk`` from it and looks the note up. The SERVICE certifies each note with
``cs1``, the same signature it has always made, over ``hex(pk)`` instead of a
hash, so a recipient can check issuance offline.

The names mirror lnurlcash-kit's TypeScript, which takes them from
lnurl-wallet's ``src/lib``, in snake_case. Where the spec text and that code
disagree, this follows the code: see :func:`derive_cash_address_node`. Graded
against lnurlcash-conformance's ``vectors/part2.json``, which is built from the
primitives and matches vectors generated from lnurl-wallet and checked against
lnurl-mint.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256

from coincurve import PrivateKey, PublicKey

from . import bech32
from .cash import CashNode, derive_cash_child, derive_cash_domain_node, derive_cash_root
from .errors import ProtocolError
from .secrets import hash_k1, is_preimage

_HARDENED = 0x80000000
_CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---- bech32m ----
#
# Each type has a fixed payload length, so there is no length limit to pick:
# ck1, cs1 and cx1 all exceed BIP-173's 90 characters, which the spec
# deliberately does not adopt. Mixed case is refused, as BIP-350 requires and
# lnurl-mint does; all-uppercase is the same string.


def _encode_fixed(hrp: str, payload: bytes, length: int) -> str:
    if len(payload) != length:
        raise ProtocolError(f"a {hrp}1 payload is {length} bytes, not {len(payload)}")
    return bech32.encode(hrp, bytes(payload), constant=bech32.BECH32M)


def _decode_fixed(hrp: str, value: str, length: int) -> bytes | None:
    if not isinstance(value, str):
        return None
    decoded = bech32.decode(value.strip(), constant=bech32.BECH32M)
    if decoded is None:
        return None
    prefix, payload = decoded
    if prefix != hrp or len(payload) != length:
        return None
    return payload


def encode_cp1(pubkey_x_only: bytes) -> str:
    """A note's public key: 32-byte x-only, as BIP-340 writes it."""
    return _encode_fixed("cp", pubkey_x_only, 32)


def decode_cp1(value: str) -> bytes | None:
    return _decode_fixed("cp", value, 32)


def is_cp1(value: str) -> bool:
    return decode_cp1(value) is not None


def encode_ck1(signature: bytes) -> str:
    """A note's bearer secret: the 65-byte ``r || s || recovery id`` ownership
    signature. Whoever holds this string holds the note."""
    return _encode_fixed("ck", signature, 65)


def decode_ck1(value: str) -> bytes | None:
    return _decode_fixed("ck", value, 65)


def is_ck1(value: str) -> bool:
    return decode_ck1(value) is not None


def encode_cs1(signature: bytes) -> str:
    """A legacy fixed-prefix certificate, retained for old notes and callers.

    New code should use :func:`encode_cs1_with_amount`.
    """
    return _encode_fixed("cs", signature, 65)


def decode_cs1(value: str) -> bytes | None:
    return _decode_fixed("cs", value, 65)


def is_cs1(value: str) -> bool:
    return decode_cs1(value) is not None


@dataclass(frozen=True)
class Cs1:
    """A current amount-bearing mint certificate."""

    amount_msat: int
    signature: bytes


def _encode_cs1_amount_suffix(amount_msat: int) -> str:
    for suffix, unit in (
        ("", 100_000_000_000),
        ("m", 100_000_000),
        ("u", 100_000),
        ("n", 100),
    ):
        if amount_msat % unit == 0:
            return f"{amount_msat // unit}{suffix}"
    # One pico-BTC is 0.1 msat. Every whole msat is exactly ten pico-BTC.
    return f"{amount_msat * 10}p"


def _decode_cs1_amount_suffix(value: str) -> int | None:
    if not value:
        return None
    unit = value[-1] if value[-1] in "munp" else ""
    digits = value[:-1] if unit else value
    if not digits or not digits.isascii() or not digits.isdigit():
        return None
    number = int(digits)
    if unit == "":
        return number * 100_000_000_000
    if unit == "m":
        return number * 100_000_000
    if unit == "u":
        return number * 100_000
    if unit == "n":
        return number * 100
    if number % 10:
        return None
    return number // 10


def encode_cs1_with_amount(amount_msat: int, signature: bytes) -> str:
    """Encode a current certificate whose prefix carries ``amount_msat``
    using BOLT 11 amount suffix rules.

    The payload is the mint's recoverable signature over that same amount and
    the note key. Encoding does not sign or verify it.
    """
    if isinstance(amount_msat, bool) or not isinstance(amount_msat, int) or amount_msat < 0:
        raise ProtocolError("amount_msat must be a non-negative integer")
    return _encode_fixed("cs" + _encode_cs1_amount_suffix(amount_msat), signature, 65)


def decode_cs1_with_amount(value: str) -> Cs1 | None:
    """Decode a current certificate and the amount carried by its prefix.

    The legacy fixed ``cs`` prefix returns ``None`` because it carries no
    amount.
    """
    if not isinstance(value, str):
        return None
    decoded = bech32.decode(value.strip(), constant=bech32.BECH32M)
    if decoded is None:
        return None
    prefix, payload = decoded
    if not prefix.startswith("cs") or len(payload) != 65:
        return None
    amount_msat = _decode_cs1_amount_suffix(prefix[2:])
    if amount_msat is None:
        return None
    return Cs1(amount_msat, payload)


def is_cs1_with_amount(value: str) -> bool:
    return decode_cs1_with_amount(value) is not None


def decode_any_cs1(value: str) -> bytes | None:
    """Return the signature from either a current or legacy certificate."""
    current = decode_cs1_with_amount(value)
    return current.signature if current is not None else decode_cs1(value)


def is_any_cs1(value: str) -> bool:
    return decode_any_cs1(value) is not None


@dataclass(frozen=True)
class Cx1:
    """A watch-only branch: its x-only public key and chain code.

    Anyone holding one can list every note key on the branch, and link them,
    but cannot spend any. Not secret the way a :class:`CashNode` is, but not
    something to publish either.
    """

    pubkey_x_only: bytes
    chain_code: bytes


def encode_cx1(pubkey_x_only: bytes, chain_code: bytes) -> str:
    if len(pubkey_x_only) != 32 or len(chain_code) != 32:
        raise ProtocolError(
            "a cx1 is a 32-byte x-only public key and a 32-byte chain code"
        )
    return _encode_fixed("cx", bytes(pubkey_x_only) + bytes(chain_code), 64)


def decode_cx1(value: str) -> Cx1 | None:
    payload = _decode_fixed("cx", value, 64)
    return Cx1(payload[:32], payload[32:]) if payload is not None else None


def is_cx1(value: str) -> bool:
    return decode_cx1(value) is not None


# ---- the per-note key tweak ----
#
#     t    = tagged_hash("LNURLcash/derive", P || chainCode || ser32_be(i))
#     pk_i = x(lift_x(P) + t*G)
#     sk_i = ((P has even y ? p : n - p) + t) mod n
#
# BIP-341's taproot tweak, so a watcher holding only the cx1 computes the same
# pk_i the holder does. i is any uint32 and is never hardened. The 4-byte
# big-endian width is what lnurl-wallet and lnurl-mint both use; the spec text
# does not pin it.

_NOTE_DERIVE_TAG = sha256(b"LNURLcash/derive").digest()


def _unusable(index: int) -> ProtocolError:
    return ProtocolError(
        f"note index {index} is unusable on this branch - use the next index"
    )


def _require_uint32(index: int) -> int:
    # bool is an int to Python, and True is not an index anyone meant
    if isinstance(index, bool) or not isinstance(index, int):
        raise ProtocolError(f"a note index must be a uint32, not {index!r}")
    if not 0 <= index <= 0xFFFFFFFF:
        raise ProtocolError(f"a note index must be a uint32, not {index}")
    return index


def _tweak_for(pubkey_x_only: bytes, chain_code: bytes, index: int) -> int:
    if len(pubkey_x_only) != 32 or len(chain_code) != 32:
        raise ProtocolError(
            "a branch is a 32-byte x-only public key and a 32-byte chain code"
        )
    ser = _require_uint32(index).to_bytes(4, "big")
    material = _NOTE_DERIVE_TAG + _NOTE_DERIVE_TAG + pubkey_x_only + chain_code + ser
    t = int.from_bytes(sha256(material).digest(), "big")
    # BIP-341 refuses t >= n rather than reducing it, and so does lnurl-mint.
    # A ~2^-128 event, but a wrong key here is a note nobody can find.
    if t >= _CURVE_N:
        raise _unusable(index)
    return t


def derive_note_pubkey(
    branch_pubkey_x_only: bytes, chain_code: bytes, index: int
) -> bytes:
    """The i-th note's x-only public key, from the branch's public half alone.

    Watch-only: it needs no private key, which is what lets a SERVICE holding
    a registered cx1 mint straight to the holder's next key.
    """
    branch_x = bytes(branch_pubkey_x_only)
    t = _tweak_for(branch_x, bytes(chain_code), index)
    try:
        branch = PublicKey(b"\x02" + branch_x)
    except ValueError as err:
        raise ProtocolError("that branch key is not a point on secp256k1") from err
    if t == 0:
        return branch_x
    try:
        # P + t*G. coincurve refuses the point at infinity, the one other way
        # an index can be unusable
        note = branch.add(t.to_bytes(32, "big"))
    except ValueError as err:
        raise _unusable(index) from err
    return note.format(compressed=True)[1:]


def derive_note_secret_key(
    branch_private_key: bytes, chain_code: bytes, index: int
) -> bytes:
    """The holder's half: the i-th note's 32-byte secret key.

    The branch key's own point may have odd y, and a cx1 carries only x, which
    names the even-y point, so the key is negated first. Without that the note
    keys would not match what a watcher derives from the cx1.
    """
    key = bytes(branch_private_key)
    p = int.from_bytes(key, "big")
    if len(key) != 32 or not 0 < p < _CURVE_N:
        raise ProtocolError("a branch private key is a 32-byte scalar in [1, n)")
    branch = PrivateKey(key).public_key.format(compressed=True)
    t = _tweak_for(branch[1:], bytes(chain_code), index)
    even = p if branch[0] == 0x02 else _CURVE_N - p
    note = (even + t) % _CURVE_N
    if note == 0:
        raise _unusable(index)
    return note.to_bytes(32, "big")


# ---- ownership proofs ----
#
#     message = "LNURLcash"
#     digest  = sha256(sha256("Lightning Signed Message:" || message))
#
# One fixed message for every note, so the value submitted to spend a note is
# the value shown to prove it. RFC6979 makes it deterministic, so re-deriving a
# key reproduces the same ck1. Other valid signatures by the same key exist,
# though (a high-S twin, or a signer with a different nonce), so a note is
# identified by the key its ck1 recovers to, never by the string.

_LIGHTNING_SIGNED_MESSAGE_PREFIX = b"Lightning Signed Message:"
_NOTE_OWNERSHIP_DIGEST = sha256(
    sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + b"LNURLcash").digest()
).digest()


def sign_note_ownership(secret_key: bytes) -> bytes:
    """The raw 65 bytes, ``r || s || recovery id``. Encode with
    :func:`encode_ck1` for the wire.

    libsecp256k1 signs with RFC6979 nonces and always returns low-S, and
    coincurve lays a recoverable signature out with the recovery id last,
    which is already the wire order.
    """
    key = bytes(secret_key)
    # checked here because coincurve zero-pads a short key rather than
    # refusing it, and a short key is somebody's bug
    if len(key) != 32:
        raise ProtocolError("a note secret key is 32 bytes")
    try:
        signer = PrivateKey(key)
    except ValueError as err:
        raise ProtocolError("a note secret key is a scalar in [1, n)") from err
    return signer.sign_recoverable(_NOTE_OWNERSHIP_DIGEST, hasher=None)


def recover_note_ownership_pubkey(signature: bytes) -> bytes | None:
    """The note's x-only public key, recovered offline from its ownership
    signature, or None if the signature does not recover. Never raises."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 65:
        return None
    try:
        recovered = PublicKey.from_signature_and_message(
            bytes(signature), _NOTE_OWNERSHIP_DIGEST, hasher=None
        )
    except Exception:
        # a recovery id above 3, r or s out of range, or no point at all
        return None
    return recovered.format(compressed=True)[1:]


# ---- a note's k1, either kind ----


def note_id_of(k1: str) -> str | None:
    """The id a SERVICE files a note under: ``sha256(k1)`` for a Part 1
    secret, and the recovered public key, as hex, for a Part 2 ck1.

    None for anything else, including a ck1 that does not recover. Two
    different ck1 strings can share an id, so compare notes by this, never by
    k1.
    """
    if not isinstance(k1, str):
        return None
    value = k1.strip().lower()
    if is_preimage(value):
        return hash_k1(value)
    signature = decode_ck1(value)
    pubkey = recover_note_ownership_pubkey(signature) if signature is not None else None
    return pubkey.hex() if pubkey is not None else None


def note_lookup_of(k1: str) -> str | None:
    """What to look a note up by without disclosing it: the hash for a Part 1
    secret, and its cp1 for a Part 2 note, which also brings its certificate
    back. Pass it to
    :func:`~lnurlcash_kit.protocol.note_info_by_hash_request`."""
    note_id = note_id_of(k1)
    if note_id is None:
        return None
    return encode_cp1(bytes.fromhex(note_id)) if is_ck1(k1.strip().lower()) else note_id


# ---- the address branch ----


def derive_cash_address_node(root: CashNode, host: str) -> CashNode:
    """``m/139'/1'/d1/d2/d3/d4`` for one mint, with ``d1..d4`` from
    HMAC-SHA256(key = the private key at ``m/139'/1'/0``, msg = host), used
    exactly as they fall, as LUD-05 does.

    This is lnurl-wallet's path, and it is the one to use. The spec text roots
    the branch at ``m/139'/d1..d4``, the very node the Part 1 ladder
    (:func:`~lnurlcash_kit.cash.derive_cash_domain_node`) already uses, so a
    wallet following the text would find none of the reference wallet's notes.

    Bearer material for every note on the branch. Hand out
    :func:`cash_node_to_cx1` of it, never the node.
    """
    return derive_cash_domain_node(derive_cash_child(root, 1 + _HARDENED), host)


def cash_node_to_cx1(node: CashNode) -> Cx1:
    """A node's watch-only half: what :func:`encode_cx1` encodes."""
    try:
        point = PrivateKey(node.private_key).public_key.format(compressed=True)
    except ValueError as err:
        raise ProtocolError("cash node holds an invalid private key") from err
    return Cx1(point[1:], bytes(node.chain_code))


# ---- a branch rooted in a Nostr key ----
#
# An extension, not LUD-25. A lightning address on a Nostr-native mint belongs
# to an npub, and a holder with no BIP-39 words - a hardware signer that keeps
# only its identity key, or a wallet that never made any - can still be paid to
# keys of its own:
#
#     seed = HMAC-SHA256(key = the identity's secret key, msg = "LNURLcash/nostr-seed")
#
# then lnurl-wallet's address path from that seed, unchanged. heartwood-esp32
# derives exactly this on the device, and lnurlcash-conformance's
# vectors/nostr-seed.json holds both to it. The identity key rebuilds every
# note paid to the branch, so whoever can restore that key can recover the
# notes, with or without the device that received them. A mint sees an
# ordinary cx1 either way.

NOSTR_CASH_SEED_LABEL = "LNURLcash/nostr-seed"


def derive_nostr_cash_seed(secret_key: bytes) -> bytes:
    """The 32-byte seed a Nostr identity's branch grows from. ``secret_key``
    is the raw 32 bytes an nsec encodes."""
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != 32:
        raise ProtocolError("a Nostr secret key is 32 bytes")
    return hmac.new(
        bytes(secret_key), NOSTR_CASH_SEED_LABEL.encode("utf-8"), sha256
    ).digest()


def derive_nostr_address_node(secret_key: bytes, host: str) -> CashNode:
    """One mint's address branch for a Nostr identity. Bearer material, like
    any address node: hand out :func:`cash_node_to_cx1` of it."""
    return derive_cash_address_node(
        derive_cash_root(derive_nostr_cash_seed(secret_key)), host
    )
