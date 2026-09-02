"""Clients. Both do the same thing; only the await keyword differs.

Everything about the protocol lives in :mod:`lnurlcash_kit.protocol`, so the
sync and async paths cannot disagree about what a response means. What lives
here is the part that genuinely differs: performing the GET, and classifying
its failure by whether the request could have been processed.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx

from . import protocol
from .errors import (
    AmbiguousMint,
    AmbiguousMutation,
    NoteSpent,
    NoteUnknown,
    RequestRefused,
)
from .note import with_new_k1
from .protocol import (
    InvoiceResult,
    MeltResult,
    MintAddressInfo,
    MutationResult,
    PayRequestInfo,
    Request,
    RotateResult,
    SplitResult,
    VerifyResult,
    WithdrawRequestInfo,
)
from .secrets import generate_note_secret
from .urls import is_allowed_service_url

DEFAULT_TIMEOUT = 30.0


class _Base:
    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        offline: bool = False,
        rng: Callable[[], str] = generate_note_secret,
    ) -> None:
        #: Bounded wait. Without one a hung SERVICE blocks the caller forever.
        self.timeout = timeout
        #: Refuse to make any request at all. A caller holding notes offline
        #: deliberately can set this to be certain nothing reaches the
        #: network, rather than trusting that it happens not to.
        self.offline = offline
        #: Where replacement note secrets come from. Substitute for a hardware
        #: RNG or a deterministic test - and see secrets.generate_note_secret
        #: for what a caller takes on by doing so.
        self.rng = rng

    def _guard(self, url: str) -> None:
        if self.offline:
            raise RequestRefused("Offline mode is on - no request was made.")
        if not is_allowed_service_url(url):
            raise RequestRefused(
                "Refusing to fetch that URL - only https, or http to a "
                "loopback or .onion host, is allowed."
            )

    @staticmethod
    def _decode(response: httpx.Response) -> Any:
        try:
            return json.loads(response.text)
        except (json.JSONDecodeError, ValueError):
            raise AmbiguousMint("The service returned an unreadable response.") from None

    @staticmethod
    def _transport_failure(err: Exception) -> AmbiguousMint:
        # Transport failures are ambiguous for a mutating request: the request
        # may well have arrived, and only the answer was lost.
        if isinstance(err, httpx.TimeoutException):
            return AmbiguousMint(
                "The service took too long to respond - its answer, if any, was lost."
            )
        return AmbiguousMint(
            "Failed to reach the service - it may be offline or unreachable."
        )

    @staticmethod
    def _preserve(request: Request, err: AmbiguousMint) -> AmbiguousMint:
        """A mutation whose outcome is unknown must carry its fresh secrets
        out with it: if the request did land, they are the only copies of the
        notes the SERVICE minted."""
        if request.new_secrets:
            return AmbiguousMutation(str(err), request.new_secrets)
        return err


class LnurlcashClient(_Base):
    """Synchronous client."""

    def __init__(self, *, client: httpx.Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._client = client
        self._owned = client is None

    def _run(self, request: Request) -> Any:
        self._guard(request.url)
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            try:
                response = client.get(request.url)
            except Exception as err:
                raise self._preserve(request, self._transport_failure(err)) from err
            try:
                body = self._decode(response)
            except AmbiguousMint as err:
                raise self._preserve(request, err) from None
            try:
                return request.parse(body)
            except AmbiguousMint as err:
                raise self._preserve(request, err) from None
        finally:
            if self._owned:
                client.close()

    # ---- operations ----

    def fetch_note_info(self, url: str) -> WithdrawRequestInfo:
        return self._run(protocol.note_info_request(url))

    def fetch_mint_address(self, url: str) -> MintAddressInfo:
        return self._run(protocol.mint_address_request(url))

    def melt_note(self, callback: str, k1: str, pr: str) -> MeltResult:
        return self._run(protocol.melt_request(callback, k1, pr))

    def rotate_note(self, callback: str, k1: str) -> RotateResult:
        return self._run(protocol.rotate_request(callback, k1, rng=self.rng))

    def rotate_note_with_hash(self, callback: str, k1: str, h: str) -> MutationResult:
        return self._run(protocol.rotate_request_with_hash(callback, k1, h))

    def split_note(
        self, callback: str, k1s: list[str], amount_msat: int
    ) -> SplitResult:
        return self._run(protocol.split_request(callback, k1s, amount_msat, rng=self.rng))

    def split_note_with_hash(
        self, callback: str, k1s: list[str], amount_msat: int, h: str, h2: str
    ) -> MutationResult:
        return self._run(
            protocol.split_request_with_hash(callback, k1s, amount_msat, h, h2)
        )

    def merge_notes(self, callback: str, k1s: list[str]) -> RotateResult:
        return self._run(protocol.merge_request(callback, k1s, rng=self.rng))

    def merge_notes_with_hash(
        self, callback: str, k1s: list[str], h: str
    ) -> MutationResult:
        return self._run(protocol.merge_request_with_hash(callback, k1s, h))

    def fetch_pay_request(self, url: str) -> PayRequestInfo:
        return self._run(protocol.pay_request_request(url))

    def request_invoice(self, pay_callback: str, amount_msat: int) -> InvoiceResult:
        """A plain LUD-06 invoice. Mints nothing: it names no output."""
        return self._run(protocol.invoice_request(pay_callback, amount_msat))

    def request_mint_invoice(
        self, pay_callback: str, amount_msat: int, mint_secret: str
    ) -> InvoiceResult:
        """An invoice that mints a note the caller already holds the secret to.

        **Persist ``mint_secret`` before paying the invoice this returns.** The
        SERVICE only ever learns its hash, so it cannot help reconstruct it,
        and a paid invoice whose secret was lost is a note nobody can spend.
        """
        return self._run(
            protocol.mint_invoice_request(pay_callback, amount_msat, mint_secret)
        )

    def fetch_invoice_verification(self, verify_url: str) -> VerifyResult:
        return self._run(protocol.verify_request(verify_url))

    def probe_burned_note(self, url: str) -> str:
        """After an AmbiguousMutation: did the burn actually happen?

        ``'live'`` the request never landed, so the fresh secrets minted
        nothing. ``'gone'`` the burn landed, and the carried secrets are the
        only money left. ``'unknown'`` the probe itself failed - no
        information, so keep everything.
        """
        try:
            self.fetch_note_info(url)
            return "live"
        except (NoteSpent, NoteUnknown):
            return "gone"
        except Exception:
            return "unknown"

    def settle_note(
        self,
        base_url: str,
        k1: str,
        expected_amount_msat: int,
        signature: str | None = None,
    ) -> tuple[str, int, str | None, str]:
        """Resolve what a split's change or a merge's output is ACTUALLY worth,
        then rotate it before further use.

        Neither response carries an amount - the spec's only source of truth is
        an informational GET - and a fee-charging SERVICE may have deducted
        from a split's change or refunded into a merge's result. That GET puts
        k1 on the wire, so a rotate follows, best-effort.

        Returns ``(k1, amount_msat, signature, callback)``.
        """
        info = self.fetch_note_info(
            with_new_k1(base_url, k1, expected_amount_msat, signature)
        )
        try:
            rotated = self.rotate_note(info.callback, k1)
        except Exception:
            return (k1, info.max_withdrawable, signature, info.callback)
        return (rotated.k1, info.max_withdrawable, rotated.signature, info.callback)


class AsyncLnurlcashClient(_Base):
    """Asynchronous client. Identical semantics to :class:`LnurlcashClient`."""

    def __init__(
        self, *, client: httpx.AsyncClient | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self._client = client
        self._owned = client is None

    async def _run(self, request: Request) -> Any:
        self._guard(request.url)
        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        try:
            try:
                response = await client.get(request.url)
            except Exception as err:
                raise self._preserve(request, self._transport_failure(err)) from err
            try:
                body = self._decode(response)
            except AmbiguousMint as err:
                raise self._preserve(request, err) from None
            try:
                return request.parse(body)
            except AmbiguousMint as err:
                raise self._preserve(request, err) from None
        finally:
            if self._owned:
                await client.aclose()

    async def fetch_note_info(self, url: str) -> WithdrawRequestInfo:
        return await self._run(protocol.note_info_request(url))

    async def fetch_mint_address(self, url: str) -> MintAddressInfo:
        return await self._run(protocol.mint_address_request(url))

    async def melt_note(self, callback: str, k1: str, pr: str) -> MeltResult:
        return await self._run(protocol.melt_request(callback, k1, pr))

    async def rotate_note(self, callback: str, k1: str) -> RotateResult:
        return await self._run(protocol.rotate_request(callback, k1, rng=self.rng))

    async def rotate_note_with_hash(
        self, callback: str, k1: str, h: str
    ) -> MutationResult:
        return await self._run(protocol.rotate_request_with_hash(callback, k1, h))

    async def split_note(
        self, callback: str, k1s: list[str], amount_msat: int
    ) -> SplitResult:
        return await self._run(
            protocol.split_request(callback, k1s, amount_msat, rng=self.rng)
        )

    async def split_note_with_hash(
        self, callback: str, k1s: list[str], amount_msat: int, h: str, h2: str
    ) -> MutationResult:
        return await self._run(
            protocol.split_request_with_hash(callback, k1s, amount_msat, h, h2)
        )

    async def merge_notes(self, callback: str, k1s: list[str]) -> RotateResult:
        return await self._run(protocol.merge_request(callback, k1s, rng=self.rng))

    async def merge_notes_with_hash(
        self, callback: str, k1s: list[str], h: str
    ) -> MutationResult:
        return await self._run(protocol.merge_request_with_hash(callback, k1s, h))

    async def fetch_pay_request(self, url: str) -> PayRequestInfo:
        return await self._run(protocol.pay_request_request(url))

    async def request_invoice(
        self, pay_callback: str, amount_msat: int
    ) -> InvoiceResult:
        """A plain LUD-06 invoice. Mints nothing: it names no output."""
        return await self._run(protocol.invoice_request(pay_callback, amount_msat))

    async def request_mint_invoice(
        self, pay_callback: str, amount_msat: int, mint_secret: str
    ) -> InvoiceResult:
        """An invoice that mints a note the caller already holds the secret to.

        **Persist ``mint_secret`` before paying the invoice this returns.**
        """
        return await self._run(
            protocol.mint_invoice_request(pay_callback, amount_msat, mint_secret)
        )

    async def fetch_invoice_verification(self, verify_url: str) -> VerifyResult:
        return await self._run(protocol.verify_request(verify_url))

    async def probe_burned_note(self, url: str) -> str:
        try:
            await self.fetch_note_info(url)
            return "live"
        except (NoteSpent, NoteUnknown):
            return "gone"
        except Exception:
            return "unknown"

    async def settle_note(
        self,
        base_url: str,
        k1: str,
        expected_amount_msat: int,
        signature: str | None = None,
    ) -> tuple[str, int, str | None, str]:
        info = await self.fetch_note_info(
            with_new_k1(base_url, k1, expected_amount_msat, signature)
        )
        try:
            rotated = await self.rotate_note(info.callback, k1)
        except Exception:
            return (k1, info.max_withdrawable, signature, info.callback)
        return (rotated.k1, info.max_withdrawable, rotated.signature, info.callback)
