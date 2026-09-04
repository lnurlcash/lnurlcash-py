"""The protocol itself, with no I/O in it.

Every operation is described as a :class:`Request` - a URL to GET, a function
to parse what comes back, and the fresh secrets that must survive if the
answer is lost. The clients in :mod:`lnurlcash_kit.client` do nothing but
perform the GET and hand the body to the parser, which is why the sync and
async clients cannot drift apart in any way that matters.

It also means a caller with its own HTTP stack - an aiohttp service, a
requests-based script, something behind a proxy - can use this module
directly and never touch the clients at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .errors import (
    AmbiguousMint,
    NotePending,
    ProtocolError,
    RequestRefused,
    ServiceRejected,
    UnverifiableNote,
    classify_note_error,
)
from .fees import MintFee, parse_mint_fee
from .bolt11 import decode_bolt11_amount_msat
from .note import note_k1
from .secrets import generate_note_secret, hash_k1, is_preimage
from .urls import is_allowed_service_url


@dataclass
class Request:
    """One GET, and everything needed to interpret its outcome."""

    url: str
    parse: Callable[[Any], Any]
    #: fresh WALLET-generated secrets this request disclosed the hashes of.
    #: If the outcome is unknown they may be the only copies of notes the
    #: SERVICE has already minted, so they must ride the failure out.
    new_secrets: list[str] = field(default_factory=list)
    #: whether a client may re-send this request when the transport loses its
    #: answer. True for a rotate, split or merge, which LUD-25 requires a
    #: SERVICE to answer as a replay of the original success ("Retrying a
    #: mutation"). False for everything else, and for a melt above all: it
    #: carries ``pr``, is paid out asynchronously, and has no replay guarantee,
    #: so a second request could ask for a second payment.
    replayable: bool = False


@dataclass(frozen=True)
class Policy:
    """What this library insists a SERVICE does, rather than merely hopes.

    LUD-25 makes offline verification mandatory: a SERVICE MUST publish
    ``mintPubkey`` and MUST sign every note a rotate, split or merge mints. A
    wallet that quietly accepted unsigned notes would be handing its holder
    something nobody downstream can check, which is the exact gap offline
    verification exists to close - so the default insists.

    Set ``require_signatures`` false only to talk to a SERVICE that predates
    the requirement, and only knowing the cost.
    """

    require_signatures: bool = True


#: The strict policy, used wherever a caller states none.
DEFAULT_POLICY = Policy()


def is_compressed_pubkey(value: Any) -> bool:
    """Whether ``value`` is a compressed secp256k1 point: 33 bytes hex, the
    leading byte naming which of the two y values the x coordinate stands for.

    Checked at the response rather than at the first signature check, because
    a ``mintPubkey`` that is not one verifies nothing - and the same fault
    found later looks like a forged note instead of a broken mint.
    """
    if not isinstance(value, str):
        return False
    key = value.strip().lower()
    return (
        len(key) == 66
        and key[:2] in ("02", "03")
        and all(char in "0123456789abcdef" for char in key)
    )


@dataclass(frozen=True)
class WithdrawRequestInfo:
    callback: str
    k1: str
    max_withdrawable: int
    min_withdrawable: int = 0
    default_description: str | None = None
    #: LUD-25 makes offline verification mandatory, so a conforming SERVICE
    #: always publishes the key its notes verify against here. Only ever None
    #: when the caller passed a Policy with ``require_signatures`` false.
    mint_pubkey: str | None = None


@dataclass(frozen=True)
class MintAddressInfo:
    callback: str
    pay_link: str
    max_withdrawable: int
    min_withdrawable: int = 0
    #: the wire field is ``mintPubkey``, but at this endpoint it is never a
    #: note's signing key - always the SERVICE's own node identity
    node_pubkey: str | None = None
    node_alias: str | None = None
    node_uri: str | None = None
    node_color: str | None = None
    #: the wire field is ``nodeCapacity``, msat like every other amount here -
    #: suffixed on this side so a caller cannot read it as sats
    node_capacity_msat: int | None = None
    node_num_channels: int | None = None
    node_num_peers: int | None = None


@dataclass(frozen=True)
class PayRequestInfo:
    callback: str
    min_sendable: int
    max_sendable: int
    metadata: str
    #: Present when paying this mints a bearer note: the raw LUD-17 withdraw
    #: endpoint, in either the plain or the ``lnurlw://`` spelling. The draft
    #: says "as described in LUD-17", and LUD-17 describes both, so a WALLET
    #: accepts either unchanged.
    withdraw_link: str | None = None
    mint_pubkey: str | None = None
    #: ``None`` means the SERVICE advertised no fee, which the draft says to
    #: read as fee-free rather than as unknown.
    mint_fee: MintFee | None = None
    #: LUD-12's field, and LUD-25's minting capability. A mint MUST allow the
    #: 64 characters a hex-encoded SHA-256 commitment needs.
    comment_allowed: int | None = None
    #: Additive ForgeSworn extension: this SERVICE also accepts the same
    #: commitment as an ``h`` parameter. Never a substitute for the mandatory
    #: comment, and anything that is not exactly ``True`` reads as false.
    mint_to_hash: bool = False

    def names_mint_output(self) -> bool:
        """Whether this SERVICE can mint a current-draft LUD-25 note.

        ``mint_to_hash`` alone cannot stand in for it: that extension is
        additive and predates the comment spelling, and a SERVICE without the
        comment capacity has nowhere to put the commitment.
        """
        return (
            self.comment_allowed is not None
            and self.comment_allowed >= MINT_COMMENT_LENGTH
        )


#: The exact comment capacity minting needs: 32 bytes as lowercase hex.
MINT_COMMENT_LENGTH = 64


@dataclass(frozen=True)
class InvoiceResult:
    pr: str
    verify: str | None = None
    #: LUD-11: absent MUST be read as True, so only an explicit False counts
    disposable: bool = True


@dataclass(frozen=True)
class VerifyResult:
    settled: bool
    preimage: str | None
    pr: str


@dataclass(frozen=True)
class MeltResult:
    pr: str | None = None
    verify: str | None = None


@dataclass(frozen=True)
class MutationResult:
    signature: str | None = None
    change_signature: str | None = None


@dataclass(frozen=True)
class RotateResult:
    k1: str
    signature: str | None = None


@dataclass(frozen=True)
class SplitResult:
    k1: str
    change: str
    signature: str | None = None
    change_signature: str | None = None


def _with_params(url: str, params: list[tuple[str, str]]) -> str:
    """Append, never replace: a merge repeats the k1 parameter, and a callback
    may already carry parameters of its own."""
    parts = urlparse(url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    return urlunparse(parts._replace(query=urlencode(existing + params)))


def _optional_int(value: Any) -> int | None:
    """An informational count or amount, or nothing. A SERVICE that sends
    something other than a number for one is not worth failing the whole
    response over - these fields are display only."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _reject_error(body: Any) -> None:
    """A SERVICE's ERROR is definitive. The reason is carried through exactly
    as sent, empty included - see classify_note_error for why substituting a
    friendly default here would be a bug about somebody's money."""
    if isinstance(body, dict) and body.get("status") == "ERROR":
        reason = body.get("reason")
        raise ServiceRejected(reason if isinstance(reason, str) else "")


# ---- the informational GET ----


def note_info_request(url: str, policy: Policy = DEFAULT_POLICY) -> Request:
    """LUD-03 step one. Never burns, rotates or alters the note.

    ``sig`` is stripped before the request: it is only meaningful to a holder
    inspecting the note locally, since the SERVICE already knows what it
    signed. ``k1`` and ``amount`` are left as they are.
    """
    parts = urlparse(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "sig"]
    request_url = urlunparse(parts._replace(query=urlencode(query)))
    queried = note_k1(url)

    def parse(body: Any) -> WithdrawRequestInfo:
        try:
            _reject_error(body)
        except ServiceRejected as err:
            raise classify_note_error(err.reason) from None
        if not isinstance(body, dict) or body.get("tag") != "withdrawRequest":
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        callback = body.get("callback")
        k1 = body.get("k1")
        maximum = body.get("maxWithdrawable")
        minimum = body.get("minWithdrawable", 0)
        if not isinstance(callback, str) or not isinstance(k1, str):
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        if minimum is not None and (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or minimum < 0
            or minimum > maximum
        ):
            raise ProtocolError("Not a withdrawRequest (unexpected response).")
        # Spec MUST: the response's k1 is the bearer secret itself, never a
        # derived or opaque id. A SERVICE returning something else for the k1
        # it was queried with is non-compliant - or the note was rotated by
        # somebody else, which matters more.
        if queried and k1.lower() != queried:
            raise ProtocolError(
                "The service echoed back a different k1 than was queried - the "
                "note may have been redeemed elsewhere, or the service isn't "
                "spec-compliant."
            )
        mint_pubkey = body.get("mintPubkey")
        # Separate from the shape check above, and separately worded: this
        # response IS a withdrawRequest, it just describes a note nobody can
        # check offline. Saying "not a withdrawRequest" would send a caller
        # after the wrong fault.
        if policy.require_signatures and not is_compressed_pubkey(mint_pubkey):
            raise ProtocolError(
                "This service publishes no mintPubkey, so its notes cannot be "
                "verified offline (LUD-25 requires one)."
                if mint_pubkey is None
                else "This service published a mintPubkey that is not a "
                "33-byte compressed secp256k1 key."
            )
        return WithdrawRequestInfo(
            callback=callback,
            k1=k1.lower(),
            max_withdrawable=maximum,
            min_withdrawable=minimum or 0,
            default_description=body.get("defaultDescription"),
            mint_pubkey=mint_pubkey.strip().lower()
            if isinstance(mint_pubkey, str)
            else None,
        )

    return Request(url=request_url, parse=parse)


def mint_address_request(url: str) -> Request:
    """LUD-25 mint address (experimental, optional). Best-effort discovery:
    most SERVICEs will not have it, and a rejection means "no extra
    information", not a failure."""

    def parse(body: Any) -> MintAddressInfo:
        _reject_error(body)
        if (
            not isinstance(body, dict)
            or body.get("tag") != "withdrawRequest"
            or not isinstance(body.get("callback"), str)
            or not isinstance(body.get("payLink"), str)
            or not isinstance(body.get("maxWithdrawable"), int)
        ):
            raise ProtocolError("Not a mint address response (unexpected shape).")
        return MintAddressInfo(
            callback=body["callback"],
            pay_link=body["payLink"],
            max_withdrawable=body["maxWithdrawable"],
            min_withdrawable=body.get("minWithdrawable", 0) or 0,
            node_pubkey=body.get("mintPubkey"),
            node_alias=body.get("nodeAlias"),
            node_uri=body.get("nodeUri"),
            node_color=body.get("nodeColor"),
            node_capacity_msat=_optional_int(body.get("nodeCapacity")),
            node_num_channels=_optional_int(body.get("nodeNumChannels")),
            node_num_peers=_optional_int(body.get("nodeNumPeers")),
        )

    return Request(url=url, parse=parse)


# ---- the mutating callback ----


def _parse_success(body: Any) -> dict:
    try:
        _reject_error(body)
    except ServiceRejected as err:
        # a k1 already mid-melt rejects every other callback naming it with
        # this exact reason string, verbatim per spec
        if err.reason == "pending":
            raise NotePending(err.reason) from None
        raise classify_note_error(err.reason) from None
    if not isinstance(body, dict) or body.get("status") != "OK":
        raise AmbiguousMint(
            "The service did not confirm the operation - it may still have been applied."
        )
    return body


def _require_signature(
    value: Any, policy: Policy, what: str
) -> str | None:
    """Every mutation the replay rule covers owes a signature over each note
    it mints, and LUD-25 no longer lets a SERVICE opt out.

    The mutation has already landed by the time this is called - ``status`` was
    OK - so the exception has to carry the caller's secrets out with it, or
    enforcing the spec becomes the thing that loses the money. ``new_secrets``
    is filled in by the client, which is what holds them.
    """
    if isinstance(value, str) and value:
        return value
    if not policy.require_signatures:
        return None
    raise UnverifiableNote(
        f"The service confirmed the {what} but returned no signature, so the "
        "note it just minted cannot be verified offline. The note exists - "
        "keep the secret."
    )


def _callback(callback: str, params: list[tuple[str, str]]) -> str:
    if not is_allowed_service_url(callback):
        raise RequestRefused("The service provided an invalid callback URL.")
    if not any(key == "k1" for key, _ in params):
        # Nothing to operate on. Worth refusing here rather than letting it
        # become a callback with no k1, whose meaning is entirely up to the
        # SERVICE - and which, read generously, could burn something the
        # caller never named.
        raise RequestRefused(
            "At least one k1 is required - there is no note to operate on."
        )
    return _with_params(callback, params)


def melt_request(callback: str, k1: str, pr: str) -> Request:
    """Burn a single note; the SERVICE pays ``pr`` of exactly its value. Merge
    several notes first to melt them together - LUD-25 dropped multi-k1 melt.

    ``{"status":"OK"}`` means the payment is IN FLIGHT, not that the note is
    spent. The SERVICE pays asynchronously and only finalises the burn once
    the payment settles, restoring the note if it fails - so a melt failure is
    never reported through this call, only observed as the note becoming
    spendable again.
    """
    url = _callback(callback, [("k1", k1), ("pr", pr.strip())])

    def parse(body: Any) -> MeltResult:
        ok = _parse_success(body)
        return MeltResult(
            pr=ok.get("pr") if isinstance(ok.get("pr"), str) else None,
            verify=ok.get("verify") if isinstance(ok.get("verify"), str) else None,
        )

    return Request(url=url, parse=parse)


def rotate_request_with_hash(
    callback: str, k1: str, h: str, policy: Policy = DEFAULT_POLICY
) -> Request:
    url = _callback(callback, [("k1", k1), ("h", h)])

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        return MutationResult(
            signature=_require_signature(ok.get("sig"), policy, "rotate")
        )

    return Request(url=url, parse=parse, replayable=True)


def split_request_with_hash(
    callback: str,
    k1s: list[str],
    amount_msat: int,
    h: str,
    h2: str,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    url = _callback(
        callback,
        [("k1", k1) for k1 in k1s]
        + [("amount", str(amount_msat)), ("h", h), ("h2", h2)],
    )

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        # Both outputs of a split are notes, and both need a signature.
        # Checked in output order so the message names the one missing.
        return MutationResult(
            signature=_require_signature(ok.get("sig"), policy, "split"),
            change_signature=_require_signature(
                ok.get("sig2"), policy, "split's change"
            ),
        )

    return Request(url=url, parse=parse, replayable=True)


def merge_request_with_hash(
    callback: str, k1s: list[str], h: str, policy: Policy = DEFAULT_POLICY
) -> Request:
    url = _callback(callback, [("k1", k1) for k1 in k1s] + [("h", h)])

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        return MutationResult(
            signature=_require_signature(ok.get("sig"), policy, "merge")
        )

    return Request(url=url, parse=parse, replayable=True)


# ---- the generating variants ----
#
# Per LUD-25 the WALLET generates the replacement secret and discloses only
# its hash. The SERVICE never sees, generates or persists it, which is what
# closes the prior-holder exposure a SERVICE-generated replacement would
# otherwise reopen on every single rotate.


def rotate_request(
    callback: str,
    k1: str,
    rng: Callable[[], str] = generate_note_secret,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    fresh = rng()
    inner = rotate_request_with_hash(callback, k1, hash_k1(fresh), policy)

    def parse(body: Any) -> RotateResult:
        result = inner.parse(body)
        return RotateResult(k1=fresh, signature=result.signature)

    return Request(url=inner.url, parse=parse, new_secrets=[fresh], replayable=True)


def split_request(
    callback: str,
    k1s: list[str],
    amount_msat: int,
    rng: Callable[[], str] = generate_note_secret,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    fresh = rng()
    change = rng()
    inner = split_request_with_hash(
        callback, k1s, amount_msat, hash_k1(fresh), hash_k1(change), policy
    )

    def parse(body: Any) -> SplitResult:
        result = inner.parse(body)
        return SplitResult(
            k1=fresh,
            change=change,
            signature=result.signature,
            change_signature=result.change_signature,
        )

    return Request(
        url=inner.url, parse=parse, new_secrets=[fresh, change], replayable=True
    )


def merge_request(
    callback: str,
    k1s: list[str],
    rng: Callable[[], str] = generate_note_secret,
    policy: Policy = DEFAULT_POLICY,
) -> Request:
    fresh = rng()
    inner = merge_request_with_hash(callback, k1s, hash_k1(fresh), policy)

    def parse(body: Any) -> RotateResult:
        result = inner.parse(body)
        return RotateResult(k1=fresh, signature=result.signature)

    return Request(url=inner.url, parse=parse, new_secrets=[fresh], replayable=True)


# ---- minting ----


def pay_request_request(url: str) -> Request:
    def parse(body: Any) -> PayRequestInfo:
        _reject_error(body)
        if (
            not isinstance(body, dict)
            or body.get("tag") != "payRequest"
            or not isinstance(body.get("callback"), str)
        ):
            raise ProtocolError("Not a payRequest (unexpected response).")
        metadata = body.get("metadata")
        # A withdrawLink that is present but not a string is a broken mint,
        # not a mint without one. Reading it as absent would send the caller
        # down the well-known fallback and quietly mint against the wrong
        # endpoint.
        withdraw_link = body.get("withdrawLink")
        if withdraw_link is not None and not isinstance(withdraw_link, str):
            raise ProtocolError("The mint's payRequest has an invalid withdrawLink.")
        comment_allowed = body.get("commentAllowed")
        if not isinstance(comment_allowed, int) or isinstance(comment_allowed, bool):
            comment_allowed = None
        info = PayRequestInfo(
            callback=body["callback"],
            min_sendable=body.get("minSendable", 0),
            max_sendable=body.get("maxSendable", 0),
            metadata=metadata if isinstance(metadata, str) else "",
            withdraw_link=withdraw_link,
            mint_pubkey=body.get("mintPubkey"),
            mint_fee=parse_mint_fee(metadata) if isinstance(metadata, str) else None,
            comment_allowed=comment_allowed,
            mint_to_hash=body.get("mintToHash") is True,
        )
        # LUD-25: minting is comment-bound. A payRequest that advertises a
        # withdrawLink but no room for the 64-character commitment is offering
        # something it cannot deliver, and the failure would otherwise land
        # after the caller had already paid.
        if info.withdraw_link is not None and not info.names_mint_output():
            raise ProtocolError(
                "This mint offers no room for the required output commitment "
                "- it cannot mint."
            )
        return info

    return Request(url=url, parse=parse)


def invoice_request(pay_callback: str, amount_msat: int) -> Request:
    """A plain LUD-06 invoice request.

    Correct for paying an ordinary Lightning address; it mints nothing,
    because it names no output. To mint, use :func:`mint_invoice_request`.
    """
    url = _with_params(pay_callback, [("amount", str(amount_msat))])

    def parse(body: Any) -> InvoiceResult:
        _reject_error(body)
        if not isinstance(body, dict) or not isinstance(body.get("pr"), str):
            raise ProtocolError("The service did not return an invoice.")
        # A SERVICE answering an amount request with an invoice for a
        # DIFFERENT amount is broken or hostile. An amountless invoice passes
        # through: there is nothing to check it against here.
        invoiced = decode_bolt11_amount_msat(body["pr"])
        if invoiced is not None and invoiced != amount_msat:
            raise ProtocolError(
                f"The service returned an invoice for {invoiced} msat, "
                f"not the {amount_msat} requested."
            )
        return InvoiceResult(
            pr=body["pr"],
            verify=body.get("verify") if isinstance(body.get("verify"), str) else None,
            disposable=body.get("disposable") is not False,
        )

    return Request(url=url, parse=parse)


def mint_invoice_request_with_hash(
    pay_callback: str, amount_msat: int, h: str
) -> Request:
    """Ask for a mint invoice, naming the note it will credit.

    ``h`` is ``sha256(secret)`` for a secret only the WALLET holds. LUD-25
    carries it as a mandatory LUD-12 ``comment``; ``h`` repeats the identical
    value for SERVICEs that took the parameter form first. It is never an
    alternative to the comment.

    The SERVICE learns a hash and nothing else, so the payment preimage is
    settlement proof only - it can never redeem the note. That is the whole
    point of the current draft: a preimage propagates to every routing node
    that forwards the payment, and a note keyed by one is a note they can all
    spend.
    """
    h = h.strip().lower()
    # Refused here rather than sent, so a WALLET never pays for a quote the
    # SERVICE was always going to reject.
    if not is_preimage(h):
        raise RequestRefused(
            "An output commitment must be 32 bytes of hex "
            "- no invoice was requested."
        )
    # The response shape is an ordinary LUD-06 invoice; reuse its parser
    # rather than restating it.
    inner = invoice_request(pay_callback, amount_msat)
    url = _with_params(
        pay_callback,
        [("amount", str(amount_msat)), ("comment", h), ("h", h)],
    )
    return Request(url=url, parse=inner.parse)


def mint_invoice_request(
    pay_callback: str, amount_msat: int, mint_secret: str
) -> Request:
    """:func:`mint_invoice_request_with_hash`, from the secret itself.

    The secret comes back on :attr:`Request.new_secrets`. **Persist it before
    paying the invoice this returns.** Paying for a note and then losing its
    secret is the one way the comment-bound scheme is worse than the preimage
    one it replaced, and persisting first removes it entirely. Drawing the
    secret from the seed derivation rather than the CSPRNG makes the note
    recoverable from birth, without any rotate at all.
    """
    # Checked before hashing, so a malformed secret is RequestRefused - the
    # caller's own input, nothing sent - rather than an error that accuses the
    # SERVICE of a broken response it never sent.
    if not is_preimage(mint_secret):
        raise RequestRefused(
            "A note secret must be 32 bytes of hex - no invoice was requested."
        )
    inner = mint_invoice_request_with_hash(
        pay_callback, amount_msat, hash_k1(mint_secret)
    )
    return Request(url=inner.url, parse=inner.parse, new_secrets=[mint_secret])


def verify_request(verify_url: str) -> Request:
    """LUD-21, to learn whether a mint or melt has settled.

    Under current LUD-25 this is unconditionally safe to call and its answer
    unconditionally safe to disclose: minting is comment-bound, so the
    preimage a settled invoice reveals is settlement proof and never the
    note's credential. (It was not always so. An earlier draft keyed the note
    by the payment preimage, which made this endpoint hand out the money; that
    fallback is gone.)"""

    def parse(body: Any) -> VerifyResult:
        _reject_error(body)
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("settled"), bool)
            or not isinstance(body.get("pr"), str)
        ):
            raise ProtocolError("The service returned an unexpected verify response.")
        preimage = body.get("preimage")
        return VerifyResult(
            settled=body["settled"],
            preimage=preimage if isinstance(preimage, str) else None,
            pr=body["pr"],
        )

    return Request(url=verify_url, parse=parse)
