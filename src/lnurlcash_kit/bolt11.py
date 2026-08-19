"""Only what a caller needs to bind a SERVICE's response to the payment it
asked for. No full TLV decode: the amount lives in the human-readable part,
and equality is a normalised string compare."""

from __future__ import annotations

import re

_INVOICE_RE = re.compile(r"^ln(bc|tb|bcrt|tbs|sb)[0-9]*[munp]?1[a-z0-9]+$")
_HRP_RE = re.compile(r"^ln(?:bc|tb|bcrt|tbs|sb)(\d+)?([munp])?$")

# per unit of the amount digits, relative to whole BTC, as a fraction of a
# msat expressed exactly: 1 BTC = 10^11 msat
_MSAT_PER_UNIT = {"": 100_000_000_000, "m": 100_000_000, "u": 100_000, "n": 100}


def is_bolt11_invoice(value: str) -> bool:
    """A loose shape check, anchored to actual bolt11 prefixes rather than a
    bare "ln", which a bech32 LNURL would also match."""
    return bool(_INVOICE_RE.match(value.strip().lower()))


def same_invoice(a: str, b: str) -> bool:
    """bolt11 is bech32, so case-insensitive. Used to bind a verify response,
    or a melt proof, to the exact invoice it claims to report on - a settled
    result for some OTHER invoice must never confirm this payment."""
    return a.strip().lower() == b.strip().lower()


def decode_bolt11_amount_msat(pr: str) -> int | None:
    """The amount out of an invoice's human-readable part.

    The bech32 separator is the LAST '1' in the string, since data characters
    can be '1' too. None for an amountless invoice, for anything that does not
    parse, and for a pico amount that is not a whole number of msat.
    """
    trimmed = pr.strip().lower()
    sep = trimmed.rfind("1")
    if sep < 2:
        return None
    match = _HRP_RE.match(trimmed[:sep])
    if not match:
        return None
    digits, multiplier = match.group(1), match.group(2) or ""
    if not digits:
        return None
    if multiplier == "p":
        # 1 pico-BTC is 0.1 msat, so only multiples of 10 are whole msat
        pico = int(digits)
        return pico // 10 if pico % 10 == 0 else None
    return int(digits) * _MSAT_PER_UNIT[multiplier]
