"""The error taxonomy, which is the safety-critical part of this library.

What each class means for the money involved:

    RequestRefused    nothing was sent. The note is untouched.
    ServiceRejected   the SERVICE processed the request and refused it.
                      Definitive.
    AmbiguousMint     the outcome is unknown. The request MAY have been
                      processed. Nothing may be assumed either way.
    ProtocolError     a non-mutating response did not match the spec.

Treating an ambiguous failure as a definitive one is how wallets lose money:
a rotate that times out after the SERVICE burned the input has already
minted the output, and the fresh secret the caller generated is the only
copy of it in existence.
"""

from __future__ import annotations


class LnurlcashError(Exception):
    """Base class for everything this library raises."""


class RequestRefused(LnurlcashError):
    """The request never left: offline, a URL this library will not fetch,
    or a callback URL that does not parse. Safe to treat as a no-op."""


class ProtocolError(LnurlcashError):
    """A non-mutating response that does not match the protocol."""


class ServiceRejected(LnurlcashError):
    """The SERVICE answered {"status":"ERROR"}: it processed the request and
    declined it. Definitive - the operation did not happen."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "The service rejected the request.")
        self.reason = reason


class NotePending(ServiceRejected):
    """The exact {"status":"ERROR","reason":"pending"} case: this k1 has a
    melt in flight, and every other operation on it is refused until that
    resolves. Retry shortly - never read this as spent."""

    def __init__(self, reason: str = "pending") -> None:
        super().__init__(reason)
        self.args = (
            "This note has another operation in progress - try again in a moment.",
        )


class NoteSpent(ServiceRejected):
    """The SERVICE reports the k1 as unambiguously already burned. It is
    authoritative here, so a holder may lock the note as spent without
    asking anything further."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.args = (f'This note has already been spent (service says: "{reason}").',)


class NoteUnknown(ServiceRejected):
    """The SERVICE does not recognise the k1 at all - never minted there,
    minted somewhere else, or corrupted. Distinct from NoteSpent because
    nothing here proves the holder's copy was ever real."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.args = (
            f"The service doesn't recognise this note (service says: \"{reason}\").",
        )


class AmbiguousMint(LnurlcashError):
    """The outcome is unknown. The failure happened in a window where the
    request may already have reached and been processed by the SERVICE: a
    timeout, a dropped connection, an unparseable response, or a 200 that
    did not carry the expected confirmation."""


class AmbiguousMutation(AmbiguousMint):
    """An AmbiguousMint from a rotate, split or merge, carrying the fresh
    WALLET-generated secrets whose hashes the uncertain request disclosed.

    If the request did land, these are the only copies of the outputs the
    SERVICE minted, so they ride the exception rather than vanishing with
    the frame that made them. Persist ``new_secrets`` before doing anything
    else, then probe to find out what happened.

    Order matches the operation's result shape: ``[rotated]`` for a rotate,
    ``[split_off, change]`` for a split, ``[merged]`` for a merge.
    """

    def __init__(self, message: str, new_secrets: list[str]) -> None:
        super().__init__(message)
        self.new_secrets = new_secrets


def classify_note_error(reason: str) -> ServiceRejected:
    """A SERVICE's wording for "this k1 is dead" varies by implementation and
    by endpoint. An informational GET can afford to distinguish "Note already
    spent." from "Unknown note.", while the mutating callback - an atomic,
    possibly multi-k1 request - can only say something like "Invalid or
    already spent k1.", since it cannot tell which case applies to which k1.

    The reason must be passed through exactly as the SERVICE sent it, empty
    string included. Substituting a friendly default first would be read back
    here as though the SERVICE had said it: "Unknown service error" matches
    the rule for an unknown note, and reports one on no evidence at all.
    """
    lowered = reason.lower()
    if "spent" in lowered:
        return NoteSpent(reason)
    if "unknown" in lowered or "not found" in lowered:
        return NoteUnknown(reason)
    return ServiceRejected(reason)
