"""Note secrets: where they come from, and what shape they are."""

from __future__ import annotations

import re
import secrets as _secrets
from hashlib import sha256

_PREIMAGE_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def hash_k1(k1: str) -> str:
    """A note's id: the ``h``/``h2`` a WALLET discloses on a rotate, split or
    merge, and the key a SERVICE stores the note under. Never the secret."""
    return sha256(bytes.fromhex(k1)).hexdigest()


def generate_note_secret() -> str:
    """LUD-25: for a rotate, split or merge, the WALLET - never the SERVICE -
    generates the replacement note's secret and discloses only its hash.

    A fresh 32 bytes, the same size a Lightning payment preimage is, though
    nothing is ever paid for it. Drawn from the OS CSPRNG. A caller passing
    its own generator (for a hardware RNG, or a deterministic test) takes
    responsibility for unpredictability: anything guessable is a note anyone
    can spend.
    """
    return _secrets.token_hex(32)


def is_preimage(value: str) -> bool:
    """A payment preimage, and therefore a note secret: 32 bytes hex."""
    return bool(_PREIMAGE_RE.match(value.strip()))
