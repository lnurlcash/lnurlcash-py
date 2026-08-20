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
    classify_note_error,
)
from .fees import MintFee, parse_mint_fee
from .bolt11 import decode_bolt11_amount_msat
from .note import note_k1
from .secrets import generate_note_secret, hash_k1
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


@dataclass(frozen=True)
class WithdrawRequestInfo:
    callback: str
    k1: str
    max_withdrawable: int
    min_withdrawable: int = 0
    default_description: str | None = None
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
    withdraw_link: str | None = None
    mint_pubkey: str | None = None
    mint_fee: MintFee | None = None


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


def note_info_request(url: str) -> Request:
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
        return WithdrawRequestInfo(
            callback=callback,
            k1=k1.lower(),
            max_withdrawable=maximum,
            min_withdrawable=minimum or 0,
            default_description=body.get("defaultDescription"),
            mint_pubkey=body.get("mintPubkey"),
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


def rotate_request_with_hash(callback: str, k1: str, h: str) -> Request:
    url = _callback(callback, [("k1", k1), ("h", h)])

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        return MutationResult(signature=ok.get("sig"))

    return Request(url=url, parse=parse)


def split_request_with_hash(
    callback: str, k1s: list[str], amount_msat: int, h: str, h2: str
) -> Request:
    url = _callback(
        callback,
        [("k1", k1) for k1 in k1s]
        + [("amount", str(amount_msat)), ("h", h), ("h2", h2)],
    )

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        return MutationResult(signature=ok.get("sig"), change_signature=ok.get("sig2"))

    return Request(url=url, parse=parse)


def merge_request_with_hash(callback: str, k1s: list[str], h: str) -> Request:
    url = _callback(callback, [("k1", k1) for k1 in k1s] + [("h", h)])

    def parse(body: Any) -> MutationResult:
        ok = _parse_success(body)
        return MutationResult(signature=ok.get("sig"))

    return Request(url=url, parse=parse)


# ---- the generating variants ----
#
# Per LUD-25 the WALLET generates the replacement secret and discloses only
# its hash. The SERVICE never sees, generates or persists it, which is what
# closes the prior-holder exposure a SERVICE-generated replacement would
# otherwise reopen on every single rotate.


def rotate_request(
    callback: str, k1: str, rng: Callable[[], str] = generate_note_secret
) -> Request:
    fresh = rng()
    inner = rotate_request_with_hash(callback, k1, hash_k1(fresh))

    def parse(body: Any) -> RotateResult:
        result = inner.parse(body)
        return RotateResult(k1=fresh, signature=result.signature)

    return Request(url=inner.url, parse=parse, new_secrets=[fresh])


def split_request(
    callback: str,
    k1s: list[str],
    amount_msat: int,
    rng: Callable[[], str] = generate_note_secret,
) -> Request:
    fresh = rng()
    change = rng()
    inner = split_request_with_hash(
        callback, k1s, amount_msat, hash_k1(fresh), hash_k1(change)
    )

    def parse(body: Any) -> SplitResult:
        result = inner.parse(body)
        return SplitResult(
            k1=fresh,
            change=change,
            signature=result.signature,
            change_signature=result.change_signature,
        )

    return Request(url=inner.url, parse=parse, new_secrets=[fresh, change])


def merge_request(
    callback: str, k1s: list[str], rng: Callable[[], str] = generate_note_secret
) -> Request:
    fresh = rng()
    inner = merge_request_with_hash(callback, k1s, hash_k1(fresh))

    def parse(body: Any) -> RotateResult:
        result = inner.parse(body)
        return RotateResult(k1=fresh, signature=result.signature)

    return Request(url=inner.url, parse=parse, new_secrets=[fresh])


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
        return PayRequestInfo(
            callback=body["callback"],
            min_sendable=body.get("minSendable", 0),
            max_sendable=body.get("maxSendable", 0),
            metadata=metadata if isinstance(metadata, str) else "",
            withdraw_link=body.get("withdrawLink"),
            mint_pubkey=body.get("mintPubkey"),
            mint_fee=parse_mint_fee(metadata) if isinstance(metadata, str) else None,
        )

    return Request(url=url, parse=parse)


def invoice_request(pay_callback: str, amount_msat: int) -> Request:
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


def verify_request(verify_url: str) -> Request:
    """LUD-21. For LNURLcash specifically, a settled invoice's preimage IS the
    bearer note's spend secret, and a verify GET proves nothing about who is
    asking - only that they know the payment hash, which travels inside the
    invoice itself. A caller receiving a preimage here MUST rotate
    immediately."""

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
