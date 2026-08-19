"""Note URLs: parsing what a note claims, and building the next one."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .secrets import is_preimage
from .urls import from_lud17, resolve_lnurl_input


def _query_pairs(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def _first(url: str, key: str) -> str | None:
    for k, v in _query_pairs(url):
        if k == key:
            return v
    return None


def _rebuild(url: str, pairs: list[tuple[str, str]]) -> str:
    parts = urlparse(url)
    return urlunparse(parts._replace(query=urlencode(pairs)))


def note_k1(url: str) -> str | None:
    """The secret out of a note URL, normalised to lowercase hex: it is bytes,
    not text, so casing carries no meaning, and normalising keeps duplicate
    detection and the echo check on an informational GET from treating the
    same secret in two casings as two different notes."""
    try:
        value = _first(url, "k1")
    except ValueError:
        return None
    return value.lower() if value is not None else None


def require_note_k1(url: str) -> str:
    """Like ``note_k1`` but raises. A hardware-backed note deliberately carries
    no secret in its URL, so a caller about to use one for a mutation should
    use this: it fails loudly instead of quietly sending a blank k1."""
    k1 = note_k1(url)
    if not k1:
        raise ValueError(
            "This note carries no secret in its URL - it may be held on a device."
        )
    return k1


def note_declared_amount(url: str) -> int | None:
    """What a note CLAIMS to carry. Only a claim by whoever encoded it - a
    SERVICE ignores it at the informational endpoint - so it is safe to display
    before contacting the SERVICE but must not be trusted without either a
    matching signature or a fresh online GET."""
    try:
        raw = _first(url, "amount")
    except ValueError:
        return None
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        try:
            value = float(raw)
        except ValueError:
            return None
        return int(value) if value.is_integer() else None


def note_signature(url: str) -> str | None:
    try:
        return _first(url, "sig")
    except ValueError:
        return None


def resolve_note_input(value: str) -> str | None:
    """Input only qualifies as a note if it resolves to a URL carrying a
    well-formed k1: 32 bytes hex. A k1 that is not hex would raise during
    hashing later, so it is refused at the door."""
    url = resolve_lnurl_input(value)
    if not url:
        return None
    k1 = note_k1(url)
    if not k1 or not is_preimage(k1):
        return None
    return url


def is_valid_note_input(value: str) -> bool:
    return resolve_note_input(value) is not None


def build_note_url(
    withdraw_link: str, k1: str, amount_msat: int | None = None
) -> str:
    """A withdrawLink plus a secret makes a note. Omit ``amount_msat`` when the
    real value is not known yet: the spec has a SERVICE ignore it here
    regardless, but some implementations validate it strictly, and a
    placeholder like 0 risks being rejected rather than ignored."""
    url = from_lud17(withdraw_link.strip())
    pairs = [(k, v) for k, v in _query_pairs(url) if k not in ("k1", "amount")]
    pairs.append(("k1", k1.strip().lower()))
    if amount_msat is not None:
        pairs.append(("amount", str(amount_msat)))
    return _rebuild(url, pairs)


def with_new_k1(
    url: str, k1: str, amount_msat: int, signature: str | None = None
) -> str:
    """The same note with its secret swapped out, after a rotate, split or
    merge. A signature only carries over when the response actually returned a
    fresh one: a mutation at a SERVICE without offline verification drops any
    stale sig, since it no longer matches the new secret."""
    pairs: list[tuple[str, str]] = []
    replaced = {"k1": False, "amount": False, "sig": False}
    for key, value in _query_pairs(url):
        if key == "k1":
            pairs.append((key, k1.lower()))
            replaced["k1"] = True
        elif key == "amount":
            pairs.append((key, str(amount_msat)))
            replaced["amount"] = True
        elif key == "sig":
            if signature:
                pairs.append((key, signature))
                replaced["sig"] = True
        else:
            pairs.append((key, value))
    if not replaced["k1"]:
        pairs.append(("k1", k1.lower()))
    if not replaced["amount"]:
        pairs.append(("amount", str(amount_msat)))
    if signature and not replaced["sig"]:
        pairs.append(("sig", signature))
    return _rebuild(url, pairs)


def without_k1(url: str, amount_msat: int, signature: str | None = None) -> str:
    """Like ``with_new_k1`` but removes k1 - for re-deriving a hardware-backed
    note's blank URL template after a mutation whose fresh secret now lives on
    the device rather than in this process."""
    pairs: list[tuple[str, str]] = []
    seen_amount = False
    seen_sig = False
    for key, value in _query_pairs(url):
        if key == "k1":
            continue
        if key == "amount":
            pairs.append((key, str(amount_msat)))
            seen_amount = True
        elif key == "sig":
            if signature:
                pairs.append((key, signature))
                seen_sig = True
        else:
            pairs.append((key, value))
    if not seen_amount:
        pairs.append(("amount", str(amount_msat)))
    if signature and not seen_sig:
        pairs.append(("sig", signature))
    return _rebuild(url, pairs)
