"""LUD-25 mint fees (optional).

A SERVICE signals what it withholds on minting via an extra
``["text/plain", "Mint fees: <base_fee_msat>,<fee_percent_ppm>"]`` entry in a
payRequest's metadata, so a WALLET can warn the payer up front that the note
they end up holding is worth less than the invoice they paid. A SERVICE that
omits the entry is fee-free, not unknown.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_FEE_RE = re.compile(r"^Mint fees:\s*(\d+)\s*,\s*(\d+)\s*$")

#: The digits come from a SERVICE and are unbounded in length. Python would
#: carry any of them exactly, but the shared vectors refuse anything past
#: 2^53 - the value has to mean the same thing in every implementation, and
#: elsewhere it is either imprecise or does not parse at all.
_MAX_SAFE_INT = 2**53 - 1


@dataclass(frozen=True)
class MintFee:
    base_fee_msat: int
    fee_ppm: int


def parse_mint_fee(metadata: str) -> MintFee | None:
    try:
        entries = json.loads(metadata)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 2 or entry[0] != "text/plain":
            continue
        if not isinstance(entry[1], str):
            continue
        match = _FEE_RE.match(entry[1])
        if not match:
            continue
        base_fee_msat = int(match.group(1))
        fee_ppm = int(match.group(2))
        if base_fee_msat > _MAX_SAFE_INT or fee_ppm > _MAX_SAFE_INT:
            continue
        # A fee of 100% or more can never net anything. Refusing it here is
        # also what keeps gross_up_for_mint_fee's search bounded, so a SERVICE
        # cannot stall a caller simply by advertising one.
        if fee_ppm >= 1_000_000:
            continue
        # An explicit "Mint fees: 0,0" has exactly the effect of omitting the
        # entry - treat it identically, so callers never have to special-case
        # a fee that is present but withholds nothing.
        if base_fee_msat == 0 and fee_ppm == 0:
            return None
        return MintFee(base_fee_msat=base_fee_msat, fee_ppm=fee_ppm)
    return None


def _proportional(gross_msat: int, fee_ppm: int) -> int:
    """floor(gross * ppm / 1_000_000), computed so it cannot overflow.

    Python integers are arbitrary precision, so this split is not strictly
    necessary here - it is written the same way as the ports deliberately, so
    that a discrepancy between languages is a difference in inputs rather than
    a difference in arithmetic. In Go and Rust the direct multiply overflows
    64-bit unsigned at realistic amounts: 21M BTC is 2.1e15 msat, and at
    999_999 ppm the product is about 2.1e21.
    """
    return (gross_msat // 1_000_000) * fee_ppm + (
        (gross_msat % 1_000_000) * fee_ppm
    ) // 1_000_000


def apply_mint_fee(gross_msat: int, fee: MintFee) -> int:
    """What a SERVICE is expected to credit after withholding its advertised
    fee. Only ever an estimate to show before paying: the authoritative value
    is whatever the informational GET reports once the note is claimed."""
    return max(0, gross_msat - fee.base_fee_msat - _proportional(gross_msat, fee.fee_ppm))


def gross_up_for_mint_fee(net_msat: int, fee: MintFee) -> int:
    """The SMALLEST invoice amount whose note nets ``net_msat`` after the fee.

    ``apply_mint_fee`` is non-decreasing in gross with per-msat steps of 0 or 1
    (the proportional term grows by at most 1 per msat, since ppm is below
    1_000_000), so the minimal such gross exists and binary search finds it
    exactly. The tempting alternative - estimate linearly, then walk one msat
    at a time - is both unbounded and wrong at the edge: at 999_999 ppm the
    walk is roughly a million steps, so any guard on it returns a non-minimal
    answer, and the SERVICE picks the fee.
    """
    if net_msat <= 0:
        return 0
    hi = net_msat + fee.base_fee_msat
    while apply_mint_fee(hi, fee) < net_msat:
        hi *= 2
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if apply_mint_fee(mid, fee) >= net_msat:
            hi = mid
        else:
            lo = mid + 1
    return lo


def format_fee_percent(ppm: int) -> str:
    """ppm is parts per million: /10_000 for a percent, then trim the trailing
    zeros (2000 ppm -> "0.2000" -> "0.2")."""
    text = f"{ppm / 10_000:.4f}"
    trimmed = text.rstrip("0").rstrip(".")
    return trimmed if trimmed else "0"


def describe_mint_fee(fee: MintFee) -> str:
    parts = []
    if fee.base_fee_msat > 0:
        parts.append(f"{round(fee.base_fee_msat / 1000)} sat flat")
    if fee.fee_ppm > 0:
        parts.append(f"{format_fee_percent(fee.fee_ppm)}% of the amount paid")
    return " + ".join(parts)
