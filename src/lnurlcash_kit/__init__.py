"""lnurlcash-kit - LNURLcash (LUD-25) bearer notes for Python.

A bearer note is an ordinary LUD-03 withdrawRequest link whose k1 IS the
asset::

    lnurlw://mint.example/w?k1=<secret>&amount=<msat>

Whoever knows the k1 controls the sats behind it, like a banknote. The
``amount`` alongside it is only a claim by whoever encoded the note; the
authoritative value is always ``maxWithdrawable`` from an informational GET.

Draft spec: https://github.com/lnurl/luds/pull/301

Reference implementations, both by dni and both MIT:
    mint    https://github.com/dni/lnurl-mint
    wallet  https://github.com/dni/lnurl-wallet
"""

from __future__ import annotations

from .bolt11 import decode_bolt11_amount_msat, is_bolt11_invoice, same_invoice
from .client import AsyncLnurlcashClient, LnurlcashClient
from .errors import (
    AmbiguousMint,
    AmbiguousMutation,
    LnurlcashError,
    NotePending,
    NoteSpent,
    NoteUnknown,
    ProtocolError,
    RequestRefused,
    ServiceRejected,
    UnverifiableNote,
    classify_note_error,
    new_secrets_of,
)
from .fees import (
    MintFee,
    apply_mint_fee,
    describe_mint_fee,
    format_fee_percent,
    gross_up_for_mint_fee,
    parse_mint_fee,
)
from .note import (
    build_note_info_url_by_hash,
    build_note_url,
    is_valid_note_input,
    note_declared_amount,
    note_k1,
    note_signature,
    require_note_k1,
    resolve_note_input,
    with_new_k1,
    without_k1,
)
from .protocol import (
    DEFAULT_POLICY,
    MINT_COMMENT_LENGTH,
    InvoiceResult,
    MeltResult,
    MintAddressInfo,
    MutationResult,
    PayRequestInfo,
    Policy,
    RotateResult,
    SplitResult,
    VerifyResult,
    WithdrawRequestInfo,
)
from .cash import (
    CashNode,
    CashSecretSource,
    cash_domain_indices,
    cash_node_from_hex,
    cash_node_to_hex,
    cash_secret_at,
    derive_cash_child,
    derive_cash_domain_node,
    derive_cash_root,
    derive_cash_secret,
)
from .secrets import (
    derive_note_root,
    derive_note_secret,
    generate_note_secret,
    hash_k1,
    is_preimage,
)
from .signature import (
    note_signature_digest,
    note_signature_message,
    verify_note_signature,
)
from .urls import (
    from_bech32_lnurl,
    from_lud17,
    is_allowed_service_url,
    is_bech32_lnurl,
    is_lightning_address,
    lightning_address_username,
    mint_address_url,
    resolve_lnurl_input,
    resolve_mint_input,
    server_of,
    to_bech32_lnurl,
    to_lud17w,
)

__version__ = "0.1.0"

__all__ = [
    "AsyncLnurlcashClient",
    "LnurlcashClient",
    "AmbiguousMint",
    "AmbiguousMutation",
    "DEFAULT_POLICY",
    "LnurlcashError",
    "NotePending",
    "NoteSpent",
    "NoteUnknown",
    "Policy",
    "ProtocolError",
    "RequestRefused",
    "ServiceRejected",
    "classify_note_error",
    "MintFee",
    "apply_mint_fee",
    "describe_mint_fee",
    "format_fee_percent",
    "gross_up_for_mint_fee",
    "parse_mint_fee",
    "build_note_info_url_by_hash",
    "build_note_url",
    "is_valid_note_input",
    "note_declared_amount",
    "note_k1",
    "note_signature",
    "require_note_k1",
    "resolve_note_input",
    "with_new_k1",
    "without_k1",
    "InvoiceResult",
    "MeltResult",
    "MintAddressInfo",
    "MutationResult",
    "MINT_COMMENT_LENGTH",
    "PayRequestInfo",
    "RotateResult",
    "SplitResult",
    "VerifyResult",
    "UnverifiableNote",
    "WithdrawRequestInfo",
    "new_secrets_of",
    "generate_note_secret",
    "hash_k1",
    "is_preimage",
    "CashNode",
    "CashSecretSource",
    "cash_domain_indices",
    "cash_node_from_hex",
    "cash_node_to_hex",
    "cash_secret_at",
    "derive_cash_child",
    "derive_cash_domain_node",
    "derive_cash_root",
    "derive_cash_secret",
    "derive_note_root",
    "derive_note_secret",
    "note_signature_digest",
    "note_signature_message",
    "verify_note_signature",
    "decode_bolt11_amount_msat",
    "is_bolt11_invoice",
    "same_invoice",
    "from_bech32_lnurl",
    "from_lud17",
    "is_allowed_service_url",
    "is_bech32_lnurl",
    "is_lightning_address",
    "lightning_address_username",
    "mint_address_url",
    "resolve_lnurl_input",
    "resolve_mint_input",
    "server_of",
    "to_bech32_lnurl",
    "to_lud17w",
    "__version__",
]
