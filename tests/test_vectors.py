"""Every assertion here comes from lnurlcash-conformance. Nothing in this file
states what the protocol is - the vectors do, and this suite only binds them
to the library's functions."""

from __future__ import annotations

import hashlib
import unicodedata
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from coincurve import PrivateKey, PublicKey, PublicKeyXOnly

from conftest import load_vectors
from lnurlcash_kit.protocol import (
    invoice_request,
    mint_invoice_request,
    mint_invoice_request_with_hash,
    pay_request_request,
    verify_request,
)
from lnurlcash_kit import (
    NOSTR_CASH_SEED_LABEL,
    NotePath,
    AmbiguousMint,
    Certification,
    Cs1,
    LnurlcashClient,
    LnurlcashError,
    MintFee,
    NotePending,
    NoteSpent,
    NoteUnknown,
    ServiceRejected,
    UnverifiableNote,
    address_proof_digest,
    address_proof_message,
    cash_domain_indices,
    cash_node_from_hex,
    cash_node_to_cx1,
    cash_node_to_hex,
    decode_any_cs1,
    decode_ck1,
    decode_cp1,
    decode_cs1,
    decode_cs1_with_amount,
    decode_cx1,
    derive_cash_child,
    derive_cash_domain_node,
    derive_cash_root,
    derive_note_key,
    derive_note_pubkey,
    derive_service_root,
    derive_share_node,
    derive_nostr_service_root,
    derive_note_root,
    derive_note_secret,
    derive_nostr_cash_seed,
    encode_ck1,
    encode_cp1,
    encode_cs1,
    encode_cs1_with_amount,
    encode_cx1,
    is_any_cs1,
    is_ck1,
    is_cp1,
    is_cs1,
    is_cs1_with_amount,
    is_cx1,
    note_id_of,
    note_lookup_of,
    note_signature_digest_for_hash,
    note_signature_message_for_hash,
    recover_note_ownership_pubkey,
    sign_note_ownership,
    sign_address_proof,
    verify_address_proof,
    verify_legacy_note_signature_hash,
    check_note_certificate,
    decode_legacy_cx1,
    encode_legacy_cx1,
    legacy_branch_node,
    legacy_cx1_of,
    legacy_derive_note_pubkey,
    legacy_derive_note_secret_key,
    legacy_note_signature_digest_for_hash,
    legacy_note_signature_message_for_hash,
    verify_note_signature_hash,
    verify_note_url,
    verify_spend,
    bearer_cw1,
    bearer_leaf,
    bearer_note,
    bearer_note_id,
    key_path_sighash,
    spend_domain_of,
    spend_prevout,
    spend_sig_msg,
    tap_leaf_hash,
    NUMS_KEY,
    hash_k1,
    ProtocolError,
    RequestRefused,
    apply_mint_fee,
    build_note_url,
    decode_bolt11_amount_msat,
    format_fee_percent,
    from_bech32_lnurl,
    gross_up_for_mint_fee,
    is_allowed_service_url,
    is_bolt11_invoice,
    is_preimage,
    lightning_address_username,
    mint_address_url,
    note_declared_amount,
    note_k1,
    note_signature,
    note_signature_digest,
    note_signature_message,
    parse_mint_fee,
    resolve_lnurl_input,
    resolve_mint_input,
    resolve_note_input,
    same_invoice,
    to_bech32_lnurl,
    verify_note_signature,
    with_new_k1,
    without_k1,
)


def _cases(name: str, key: str):
    return load_vectors(name)[key]


def _nested(name: str, key: str, inner: str):
    return load_vectors(name)[key][inner]


# ---- signatures ----


# signature.json predates notes keyed by Q: every certificate there is over a
# bearer note's hash h, with no domain, the message a mint signed before LUD-25
# moved certificates onto hex(Q) at the mint's domain. The verdicts still hold
# through the legacy reading, reported as such; the message a current mint
# signs for the same note is over its domain and Q instead.


@pytest.mark.parametrize("case", _cases("signature.json", "cases"), ids=lambda c: c["name"])
def test_signature_verification(case):
    want = Certification.CERTIFIED_OVER_HASH if case["valid"] else Certification.NOT_CERTIFIED
    # a bearer preimage opens its note anywhere, so the domain is moot
    got = verify_note_signature(
        case["k1"], "mint.example", case["amountMsat"], case["signature"], case["mintPubkey"]
    )
    assert got is want
    assert bool(got) is case["valid"]
    if case["valid"]:
        assert (
            check_note_certificate(
                case["noteId"], "mint.example", case["amountMsat"], case["signature"], case["mintPubkey"]
            )
            is Certification.CERTIFIED_OVER_HASH
        )
        assert verify_legacy_note_signature_hash(
            case["noteId"], case["amountMsat"], case["signature"], case["mintPubkey"]
        )
    # and never a current certificate
    assert not verify_note_signature_hash(
        case["noteId"], "mint.example", case["amountMsat"], case["signature"], case["mintPubkey"]
    )


@pytest.mark.parametrize(
    "case",
    [c for c in _cases("signature.json", "cases") if c["message"] is not None],
    ids=lambda c: c["name"],
)
def test_signature_digest_derivation(case):
    # the pre-taproot message, over h
    h = hash_k1(case["k1"])
    assert legacy_note_signature_message_for_hash(h, case["amountMsat"]) == case["message"]
    assert legacy_note_signature_digest_for_hash(h, case["amountMsat"]).hex() == case["digest"]
    # and the message a current mint signs names the note by hex(Q) at its domain
    q = bearer_note_id(h)
    assert q != h
    assert (
        note_signature_message(case["k1"], "mint.example", case["amountMsat"])
        == f"LNURLcash:mint.example:{case['amountMsat']}:{q}"
    )
    assert note_signature_digest(
        case["k1"], "mint.example", case["amountMsat"]
    ) == note_signature_digest_for_hash(q, "mint.example", case["amountMsat"])


# ---- response classification ----
#
# responses.json: what each answer to a callback means for the money. `op`
# says which call a case is driven through, and `output` and `change` which
# kind of note the mutation mints, a hash unless the case says cp1. Driven
# through the real client over a mock transport, so a dropped connection, a
# timeout and an unreadable body are graded on the client's own
# classification rather than a restatement of it. Retries are off so one case
# is one request - the replay behaviour has its own tests.

_RESPONSES = "responses.json"
_RESPONSE_CB = "https://mint.example/w/cb"
_RESPONSE_K1 = "a" * 64
# a cp1 has to name a curve point, or no conforming mint would take it
_RESPONSE_OUTPUTS = {
    "hash": "b" * 64,
    "cp1": encode_cp1(PrivateKey(bytes([0x0B]) * 32).public_key_xonly.format()),
}
_RESPONSE_CHANGES = {
    "hash": "c" * 64,
    "cp1": encode_cp1(PrivateKey(bytes([0x0D]) * 32).public_key_xonly.format()),
}
_RESPONSE_OUTCOMES = {
    "pending": NotePending,
    "spent": NoteSpent,
    "unknown": NoteUnknown,
    "ambiguous": AmbiguousMint,
    "unverifiable": UnverifiableNote,
}


def _response_cases() -> list[tuple[dict, str]]:
    """Each case with the call it goes through. A bare "mutation" is any of
    the single-output mutations, so it goes through both of them: a merge owes
    its output exactly what a rotate does."""
    driven = []
    for case in _cases(_RESPONSES, "cases"):
        for via in ("rotate", "merge") if case["op"] == "mutation" else (case["op"],):
            driven.append((case, via))
    return driven


def _answering(case: dict) -> httpx.MockTransport:
    def answer(request: httpx.Request) -> httpx.Response:
        if case.get("transportError"):
            raise httpx.ConnectError("network error", request=request)
        if case.get("timeout"):
            raise httpx.ReadTimeout("timed out", request=request)
        if "bodyRaw" in case:
            return httpx.Response(case["http"], text=case["bodyRaw"])
        return httpx.Response(case["http"], json=case["body"])

    return httpx.MockTransport(answer)


def _drive(case: dict, via: str):
    # a kind this does not know is a vector this suite cannot grade, and
    # reading it as a hash would pass it on no evidence
    output = _RESPONSE_OUTPUTS[case.get("output", "hash")]
    change = _RESPONSE_CHANGES[case.get("change", "hash")]
    with httpx.Client(transport=_answering(case)) as http:
        client = LnurlcashClient(client=http, mutation_retries=0)
        if via == "melt":
            return client.melt_note(_RESPONSE_CB, _RESPONSE_K1, "lnbc210n1pjq")
        if via == "split":
            return client.split_note_with_hash(
                _RESPONSE_CB, [_RESPONSE_K1], 5000, output, change
            )
        if via == "merge":
            return client.merge_notes_with_hash(_RESPONSE_CB, [_RESPONSE_K1], output)
        assert via == "rotate", f"no call for op {via!r}"
        return client.rotate_note_with_hash(_RESPONSE_CB, _RESPONSE_K1, output)


def test_response_vectors_name_every_outcome_this_suite_grades():
    vectors = load_vectors(_RESPONSES)
    expected = {case["expect"] for case in vectors["cases"]}
    assert expected <= set(vectors["outcomes"])
    assert expected <= set(_RESPONSE_OUTCOMES) | {"ok", "error"}
    # the cp1 cases are what this file exists to drive; losing them to a
    # renamed field would pass every hash case and grade nothing
    assert any(case.get("output") == "cp1" for case in vectors["cases"])
    assert any(case.get("change") == "cp1" for case in vectors["cases"])


@pytest.mark.parametrize(
    "case,via",
    _response_cases(),
    ids=lambda v: v if isinstance(v, str) else f"{v['expect']}: {v['name']}",
)
def test_response_classification(case, via):
    if case["expect"] == "ok":
        result = _drive(case, via)
        if via == "melt":
            return
        # Absent means none: the response fixture models no-signer mode rather
        # than something this suite merely declined to check.
        assert result.signature == case.get("signature")
        if via == "split":
            assert result.change_signature == case.get("changeSignature")
        return
    with pytest.raises(LnurlcashError) as raised:
        _drive(case, via)
    if case["expect"] == "error":
        # a definitive refusal for some other reason must not be mistaken for
        # one of the note-specific outcomes a holder acts on
        assert isinstance(raised.value, ServiceRejected)
        assert not isinstance(raised.value, (NotePending, NoteSpent, NoteUnknown))
    else:
        assert isinstance(raised.value, _RESPONSE_OUTCOMES[case["expect"]])


# ---- the informational GET ----
#
# withdraw-info.json: what a note's informational GET may answer. Driven
# through the real client over a mock transport, the way responses.json is,
# for the vector's own queried URL, so the request the client builds is graded
# alongside how it reads the answer: sig never reaches the SERVICE, and k1
# goes out exactly as the note carried it.

_WITHDRAW_INFO = "withdraw-info.json"


def _drive_note_info(case: dict) -> tuple[object, dict[str, list[str]]]:
    """What the client made of the case's body, a result or the error it
    raised, and the query it sent to get it."""
    queried = load_vectors(_WITHDRAW_INFO)["queriedUrl"]
    sent: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=case["body"])

    with httpx.Client(transport=httpx.MockTransport(answer)) as http:
        try:
            outcome: object = LnurlcashClient(client=http).fetch_note_info(queried)
        except LnurlcashError as err:
            outcome = err
    assert len(sent) == 1, "one informational GET, and nothing else"
    return outcome, parse_qs(sent[0].url.query.decode(), keep_blank_values=True)


def _assert_sent_as_queried(query: dict[str, list[str]]) -> None:
    vectors = load_vectors(_WITHDRAW_INFO)
    queried = parse_qs(urlparse(vectors["queriedUrl"]).query, keep_blank_values=True)
    for key in vectors["requestMustNotSend"]:
        assert key not in query, f"sent {key}, which the SERVICE must never see"
    for key in vectors["requestMustSendUnchanged"]:
        assert query.get(key) == queried[key], f"{key} did not go out as queried"


def test_withdraw_info_vectors_are_the_shape_this_suite_grades():
    # a field this suite does not read is one nobody is grading
    vectors = load_vectors(_WITHDRAW_INFO)
    assert vectors["version"] == 1
    assert set(vectors) == {
        "version",
        "spec",
        "description",
        "queriedUrl",
        "requestMustNotSend",
        "requestMustSendUnchanged",
        "accepted",
        "rejected",
    }
    for case in vectors["accepted"]:
        assert set(case) <= {"name", "body", "maxWithdrawable", "why"}
        assert "maxWithdrawable" in case
    for case in vectors["rejected"]:
        assert set(case) <= {"name", "body", "why"}


@pytest.mark.parametrize(
    "case", _cases(_WITHDRAW_INFO, "accepted"), ids=lambda c: c["name"]
)
def test_note_info_accepted(case):
    info, sent = _drive_note_info(case)
    _assert_sent_as_queried(sent)
    assert not isinstance(info, LnurlcashError), f"refused: {info} ({case.get('why')})"
    assert type(info.max_withdrawable) is int
    assert info.max_withdrawable == case["maxWithdrawable"]


@pytest.mark.parametrize(
    "case", _cases(_WITHDRAW_INFO, "rejected"), ids=lambda c: c["name"]
)
def test_note_info_rejected(case):
    outcome, sent = _drive_note_info(case)
    _assert_sent_as_queried(sent)
    assert isinstance(outcome, ProtocolError), (
        f"got {outcome!r}, want a ProtocolError ({case.get('why')})"
    )


# ---- bech32 ----


@pytest.mark.parametrize("case", _cases("bech32.json", "encode"))
def test_bech32_round_trip(case):
    assert to_bech32_lnurl(case["url"]) == case["lnurl"]
    assert from_bech32_lnurl(case["lnurl"]) == case["url"]


@pytest.mark.parametrize("case", _cases("bech32.json", "decodeInvalid"))
def test_bech32_rejects_invalid(case):
    assert from_bech32_lnurl(case["input"]) is None


def test_bech32_is_case_insensitive():
    case = load_vectors("bech32.json")["caseInsensitive"]
    assert from_bech32_lnurl(case["lower"]) == case["url"]
    assert from_bech32_lnurl(case["upper"]) == case["url"]


# ---- url admission ----


@pytest.mark.parametrize("url", _cases("url-admission.json", "allowed"))
def test_url_allowed(url):
    assert is_allowed_service_url(url) is True


@pytest.mark.parametrize("case", _cases("url-admission.json", "rejected"), ids=lambda c: c["why"])
def test_url_rejected(case):
    assert is_allowed_service_url(case["url"]) is False


# ---- input resolution ----


@pytest.mark.parametrize("case", _cases("input-resolution.json", "lnurl"))
def test_resolve_lnurl_input(case):
    assert resolve_lnurl_input(case["input"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("input-resolution.json", "mint"))
def test_resolve_mint_input(case):
    assert resolve_mint_input(case["input"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("input-resolution.json", "note"))
def test_resolve_note_input(case):
    assert resolve_note_input(case["input"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("input-resolution.json", "mintAddressUrl"))
def test_mint_address_url(case):
    assert mint_address_url(case["payUrl"]) == case["expect"]


@pytest.mark.parametrize(
    "case", _cases("input-resolution.json", "lightningAddressUsername")
)
def test_lightning_address_username(case):
    assert lightning_address_username(case["payUrl"]) == case["expect"]


# ---- note urls ----


@pytest.mark.parametrize("case", _cases("note-url.json", "parse"))
def test_note_url_parse(case):
    assert note_k1(case["url"]) == case["k1"]
    assert note_declared_amount(case["url"]) == case["declaredAmountMsat"]
    assert note_signature(case["url"]) == case["signature"]


@pytest.mark.parametrize("case", _cases("note-url.json", "build"))
def test_note_url_build(case):
    assert build_note_url(case["withdrawLink"], case["k1"], case["amountMsat"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("note-url.json", "withNewK1"))
def test_with_new_k1(case):
    assert (
        with_new_k1(case["url"], case["k1"], case["amountMsat"], case["signature"])
        == case["expect"]
    )


@pytest.mark.parametrize("case", _cases("note-url.json", "withoutK1"))
def test_without_k1(case):
    assert without_k1(case["url"], case["amountMsat"], case["signature"]) == case["expect"]


# ---- fees ----


def _fee(raw: dict) -> MintFee:
    # addressFeeMsat is absent from the apply and grossUp cases, which do not
    # use it
    return MintFee(
        base_fee_msat=raw["baseFeeMsat"],
        fee_ppm=raw["feePpm"],
        address_fee_msat=raw.get("addressFeeMsat"),
    )


@pytest.mark.parametrize("case", _cases("fees.json", "parse"))
def test_parse_mint_fee(case):
    parsed = parse_mint_fee(case["metadata"])
    if case["expect"] is None:
        assert parsed is None
    else:
        assert parsed == _fee(case["expect"])


@pytest.mark.parametrize("case", _cases("fees.json", "apply"))
def test_apply_mint_fee(case):
    assert apply_mint_fee(case["grossMsat"], _fee(case["fee"])) == case["expect"]


@pytest.mark.parametrize("case", _cases("fees.json", "grossUp"))
def test_gross_up_for_mint_fee(case):
    assert gross_up_for_mint_fee(case["netMsat"], _fee(case["fee"])) == case["expect"]


def test_gross_up_is_always_the_true_minimum():
    spec = load_vectors("fees.json")["grossUpRoundTrip"]
    for raw in spec["fees"]:
        fee = _fee(raw)
        for net in spec["netAmountsMsat"]:
            gross = gross_up_for_mint_fee(net, fee)
            assert apply_mint_fee(gross, fee) == net
            assert apply_mint_fee(gross - 1, fee) < net


@pytest.mark.parametrize("case", _cases("fees.json", "formatPercent"))
def test_format_fee_percent(case):
    assert format_fee_percent(case["ppm"]) == case["expect"]


# ---- bolt11 ----


@pytest.mark.parametrize("case", _cases("bolt11.json", "decodeAmountMsat"))
def test_decode_bolt11_amount(case):
    assert decode_bolt11_amount_msat(case["pr"]) == case["expect"]


@pytest.mark.parametrize("case", _cases("bolt11.json", "isInvoice"))
def test_is_bolt11_invoice(case):
    assert is_bolt11_invoice(case["pr"]) is case["expect"]


@pytest.mark.parametrize("case", _cases("bolt11.json", "sameInvoice"))
def test_same_invoice(case):
    assert same_invoice(case["a"], case["b"]) is case["expect"]


@pytest.mark.parametrize("case", _cases("bolt11.json", "isPreimage"))
def test_is_preimage(case):
    assert is_preimage(case["value"]) is case["expect"]


# ---- LUD-25 minting ----
#
# This is the suite that would have caught the library sitting on the deleted
# preimage-keyed model for a month: nothing here states an opinion of its own,
# so a draft change lands as a red test rather than as a silent divergence
# discovered by a wallet that could not mint.

_MINT_CALLBACK = "https://mint.example/p/cb"


@pytest.mark.parametrize(
    "case", _cases("pay-request.json", "accepted"), ids=lambda c: c["name"]
)
def test_pay_request_accepted(case):
    info = pay_request_request("https://mint.example/p").parse(case["body"])
    assert info.withdraw_link == case.get("withdrawLink")
    assert info.comment_allowed == case.get("commentAllowed")
    expected_fee = case.get("mintFee")
    if expected_fee is None:
        assert info.mint_fee is None
    else:
        assert info.mint_fee == MintFee(
            base_fee_msat=expected_fee["baseFeeMsat"], fee_ppm=expected_fee["feePpm"]
        )
    # A payRequest is only a mint if it can carry the commitment, and a mint is
    # only a mint if it advertises where the note will live.
    assert info.names_mint_output() is (info.withdraw_link is not None)


@pytest.mark.parametrize(
    "case", _cases("pay-request.json", "rejected"), ids=lambda c: c["name"]
)
def test_pay_request_rejected(case):
    with pytest.raises(ProtocolError):
        pay_request_request("https://mint.example/p").parse(case["body"])


@pytest.mark.parametrize(
    "case",
    _nested("pay-request.json", "mintCallback", "accepted"),
    ids=lambda c: c["name"],
)
def test_mint_callback_names_the_note(case):
    request = mint_invoice_request_with_hash(
        _MINT_CALLBACK, case["amountMsat"], case["comment"]
    )
    # LUD-25 carries the commitment as a mandatory LUD-12 comment; h repeats it
    # for the additive ForgeSworn profile.
    assert f"comment={case['comment']}" in request.url
    assert f"h={case['comment']}" in request.url
    assert f"amount={case['amountMsat']}" in request.url
    assert case["noteId"] == case["comment"]
    assert case["paymentPreimageIsBearerK1"] is False


@pytest.mark.parametrize(
    "case",
    _nested("pay-request.json", "mintCallback", "rejected"),
    ids=lambda c: c["name"],
)
def test_mint_callback_refuses_an_unnamed_output(case):
    # A null comment is the unnamed mint the draft forbids: this library cannot
    # express one, because the minting builder requires the commitment. A
    # malformed one is refused before anything is sent.
    with pytest.raises(RequestRefused):
        if case["comment"] is None:
            mint_invoice_request(_MINT_CALLBACK, case["amountMsat"], "")
        else:
            mint_invoice_request_with_hash(
                _MINT_CALLBACK, case["amountMsat"], case["comment"]
            )


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "invoice", "accepted"), ids=lambda c: c["name"]
)
def test_invoice_accepted(case):
    result = invoice_request(_MINT_CALLBACK, case["requestedMsat"]).parse(case["body"])
    assert result.disposable is case["disposable"]
    assert result.verify == case.get("verify")


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "invoice", "rejected"), ids=lambda c: c["name"]
)
def test_invoice_rejected(case):
    with pytest.raises(ProtocolError):
        invoice_request(_MINT_CALLBACK, case["requestedMsat"]).parse(case["body"])


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "verify", "accepted"), ids=lambda c: c["name"]
)
def test_verify_accepted(case):
    result = verify_request("https://mint.example/verify/abc").parse(case["body"])
    assert result.settled is case["settled"]
    assert result.preimage == case.get("preimage")


@pytest.mark.parametrize(
    "case", _nested("pay-request.json", "verify", "rejected"), ids=lambda c: c["name"]
)
def test_verify_rejected(case):
    with pytest.raises(ProtocolError):
        verify_request("https://mint.example/verify/abc").parse(case["body"])


# ---- derivation ----
#
# The two schemes a wallet may mint under. cash-derivation.json is the one
# LUD-25 specifies and the one a new wallet uses; derivation.json is the
# pre-spec HMAC scheme, kept because notes minted under it are still money.
#
# A disagreement with either file is a wallet that cannot restore what another
# implementation of the same seed phrase minted, which is the whole reason
# these vectors exist rather than each library testing itself.


def test_cash_derivation_scheme_is_the_one_this_library_implements():
    scheme = load_vectors("cash-derivation.json")["scheme"]
    assert scheme["purpose"] == "m/139'"
    # The one thing an implementation can silently get wrong: d1..d4 are raw
    # uint32, hardened only where they happen to land at or above 2^31.
    assert scheme["hardenedByMagnitudeOnly"] is True


def test_cash_derivation_matches_bip32_vector_1():
    # BIP-32's own published vector, so a failure here says CKDpriv is wrong
    # rather than the LUD-25 path above it. The chain alternates hardened and
    # unhardened, which is exactly the pair of legs the domain levels land on.
    steps = load_vectors("cash-derivation.json")["bip32Vector1"]
    node = cash_node_from_hex(steps[0]["node"])
    for step in steps[1:]:
        node = derive_cash_child(node, step["index"])
        assert cash_node_to_hex(node) == step["node"]


@pytest.mark.parametrize(
    "case", _cases("cash-derivation.json", "cases"), ids=lambda c: c["name"]
)
def test_cash_derivation(case):
    seed = bytes.fromhex(case["seedHex"])
    root = derive_cash_root(seed)
    assert cash_node_to_hex(root) == case["cashRoot"]
    assert list(cash_domain_indices(root, case["host"])) == case["domainIndices"]

    domain_node = derive_cash_domain_node(root, case["host"])
    assert cash_node_to_hex(domain_node) == case["domainNode"]


def test_legacy_derivation_scheme():
    assert load_vectors("derivation.json")["scheme"]["rootKey"] == "lnurlcash-note-v1"


@pytest.mark.parametrize("case", _cases("derivation.json", "cases"), ids=lambda c: c["name"])
def test_legacy_derivation(case):
    root = derive_note_root(bytes.fromhex(case["seedHex"]))
    k1 = derive_note_secret(root, case["host"], case["index"])
    assert k1 == case["k1"]
    assert hash_k1(k1) == case["noteId"]




# ---- key-path notes ----
#
# part2.json pins LUD-26's tree below each SERVICE root, each key's key-path
# spend for its domain, share cx1s, address proofs, mint certificates, the
# superseded tweak schemes and the bech32m strings. Every field is graded on
# every branch and note: a wallet that disagrees with one of them cannot find,
# spend or check a note that another implementation of the same seed made.

_PART2 = "part2.json"
_HARDENED = 0x80000000
_PART2_DECODERS = {
    "cp1": decode_cp1,
    "ck1": decode_ck1,
    "cs1": lambda value: (
        certificate.signature
        if (certificate := decode_cs1_with_amount(value)) is not None
        else None
    ),
    "cx1": lambda value: (
        cx1.chain_code + cx1.pubkey if (cx1 := decode_cx1(value)) is not None else None
    ),
}
_PART2_TESTS = {
    "cp1": is_cp1,
    "ck1": is_ck1,
    "cs1": is_cs1_with_amount,
    "cx1": is_cx1,
}


def _bip39_seed(mnemonic: str) -> bytes:
    """BIP-39's phrase-to-seed step, with no passphrase.

    The library deliberately takes raw seed bytes and never a phrase, which
    keeps a wordlist out of every consumer's environment. But the vectors
    carry the phrase too, so the step that joins the two is graded here rather
    than taken on trust.
    """
    phrase = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", phrase, b"mnemonic", 2048)


def _branch_id(branch: dict) -> str:
    return f"{branch['mnemonic'].split()[0]}/{branch['host']}"


def _all_notes(accounts: list[dict]) -> list[dict]:
    notes: list[dict] = []
    for account in accounts:
        notes += account["wallet"] + account["change"]
        for share in account["shares"]:
            notes += share["notes"]
    return notes


def _x_only(secret_key: bytes) -> str:
    return PrivateKey(secret_key).public_key_xonly.format().hex()


def _grade_key_path_note(note: dict, secret: bytes, host: str, domain: str, at: str) -> None:
    """One key-path note's spend fields, as part2.json and nostr-seed.json both
    carry them: the sighash for its domain, the signature, the ck1, and what
    the SERVICE makes of it there and elsewhere."""
    pubkey = bytes.fromhex(note["notePubkey"])
    assert key_path_sighash(pubkey, domain).hex() == note["sighash"], at
    # Fixed BIP-340 auxiliary input: the same key reproduces the same ck1 for
    # the same domain byte for byte, for seed recovery. Signing from the host
    # as stored reduces it to the domain first.
    payload = sign_note_ownership(secret, host)
    assert payload[:32] == pubkey, at
    assert payload[32:].hex() == note["keyPathSignature"], at
    assert encode_ck1(payload) == note["ck1"], at
    assert decode_ck1(note["ck1"]) == payload, at

    # Verified twice: through the library, and straight off the vector's own
    # sighash, which pins exactly what the library signs over.
    owner = recover_note_ownership_pubkey(payload, domain)
    assert owner is not None and owner.pubkey_x_only == pubkey and not owner.legacy, at
    assert PublicKeyXOnly(pubkey).verify(payload[32:], bytes.fromhex(note["sighash"])), at
    verified = verify_spend(note["ck1"], domain)
    assert verified is not None and verified.output_key == pubkey and not verified.legacy, at
    # and it is bound to that mint: anywhere else it opens nothing
    assert verify_spend(note["ck1"], "elsewhere.example") is None, at

    assert note_id_of(note["ck1"]) == note["notePubkey"], at
    assert note_id_of(note["ck1"].upper()) == note["notePubkey"], at
    assert note_lookup_of(note["ck1"]) == note["cp1"], at


def _grade_note(service_root, path: NotePath, note: dict, host: str, domain: str, at: str):
    """One note's keys, derived from the SERVICE root at ``path``, and its spend."""
    key = derive_note_key(service_root, path)
    assert key.secret_key.hex() == note["noteSecretKey"], at
    assert key.pubkey.hex() == note["notePubkeyCompressed"], at
    assert key.output_key.hex() == note["notePubkey"], at
    # x(sk . G) == Q, the round trip the spec calls out
    assert _x_only(key.secret_key) == note["notePubkey"], at
    assert encode_cp1(key.output_key) == note["cp1"], at
    assert decode_cp1(note["cp1"]) == key.output_key, at
    _grade_key_path_note(note, key.secret_key, host, domain, at)


def _grade_accounts(service_root, accounts: list[dict], host: str, domain: str, at: str) -> None:
    """Every account as part2.json and nostr-seed.json carry them: each wallet
    and change note from the root, each share's cx1, and each share note both
    from the root and, as a SERVICE derives it, from the cx1 alone."""
    for account in accounts:
        a = account["account"]
        for chain, make in (("wallet", NotePath.wallet), ("change", NotePath.change)):
            for note in account[chain]:
                index = note["index"]
                _grade_note(
                    service_root,
                    make(a, index),
                    note,
                    host,
                    domain,
                    f"{at} {a}'/{chain}/{index}",
                )
        for share in account["shares"]:
            n = share["share"]
            where = f"{at} {a}'/2/{n}'"
            node = derive_share_node(service_root, a, n)
            assert node.private_key.hex() == share["sharePrivateKey"], where
            assert node.chain_code.hex() == share["chainCode"], where
            cx1 = cash_node_to_cx1(node)
            assert cx1.pubkey.hex() == share["sharePubkey"], where
            assert encode_cx1(cx1) == share["cx1"], where
            assert len(share["cx1"]) == 113, where
            # a SERVICE starts from the string, never the node
            watched = decode_cx1(share["cx1"])
            assert watched == cx1, where
            for note in share["notes"]:
                index = note["index"]
                _grade_note(
                    service_root,
                    NotePath.for_share(a, n, index),
                    note,
                    host,
                    domain,
                    f"{where}/{index}",
                )
                assert derive_note_pubkey(watched, index).hex() == note["notePubkey"], (
                    f"{where}/{index}: CKDpub from the cx1"
                )


def test_part2_conventions_are_the_ones_this_library_implements():
    conventions = load_vectors(_PART2)["conventions"]
    assert conventions["serviceRoot"] == "m/139'/d1/d2/d3/d4"
    assert conventions["hashingKey"] == "m/139'/0"
    assert conventions["walletChain"] == "S/a'/0/i"
    assert conventions["changeChain"] == "S/a'/1/i"
    assert conventions["shareNote"] == "S/a'/2/n'/i"
    assert conventions["spendDomain"].startswith("the host's lowercase name")
    assert conventions["ck1Signs"].startswith('tagged_hash("TapSighash", 0x00 || SigMsg)')
    assert conventions["keyPathSignature"].startswith("BIP-340 Schnorr, 64 bytes, all-zero aux_rand")
    assert conventions["ck1Payload"] == "32-byte x-only public key || 64-byte Schnorr signature"
    assert conventions["cx1Payload"].startswith("chainCode (32) || P (33, compressed)")
    assert conventions["addressProofMessages"] == {
        "register": "LNURLcash:register:<domain>:<username>:<cx1>",
        "update": "LNURLcash:update:<domain>:<username>:<new cx1>",
        "unregister": "LNURLcash:unregister:<domain>:<username>",
    }
    assert conventions["certificateMessage"] == "LNURLcash:<domain>:<amount_msat>:<hex(Q)>"
    assert conventions["certificateHrp"] == "cs || BOLT11_amount_suffix(amount_msat)"
    # the sighash itself is bound in _grade_key_path_note, by reproducing every
    # vector's sighash and signature


def test_part2_covers_both_parities_the_largest_index_and_a_host_with_a_port():
    branches = load_vectors(_PART2)["branches"]
    notes = [n for b in branches for n in _all_notes(b["accounts"])]
    # both parities exercise the BIP-340 signer's negation, and 2^31 - 1 is the
    # largest index that is not a hardened step
    assert any(n["notePubkeyCompressed"].startswith("02") for n in notes)
    assert any(n["notePubkeyCompressed"].startswith("03") for n in notes)
    assert any(n["index"] == 0x7FFFFFFF for n in notes)
    # where the host as stored and the domain part company
    assert any(b["host"] != b["domain"] for b in branches)


@pytest.mark.parametrize("branch", _cases(_PART2, "branches"), ids=_branch_id)
def test_part2_branch(branch):
    host, domain = branch["host"], branch["domain"]
    assert spend_domain_of(host) == domain
    seed = _bip39_seed(branch["mnemonic"])
    assert seed.hex() == branch["seedHex"]
    root = derive_cash_root(seed)
    # the hashing key is m/139'/0, so the four levels hang off the root itself
    assert derive_cash_child(root, 0).private_key.hex() == branch["cashHashingKey"]
    assert list(cash_domain_indices(root, domain)) == branch["domainIndices"]
    # from the host as stored, which drops its port first
    service_root = derive_service_root(root, host)
    assert cash_node_to_hex(service_root) == branch["serviceRoot"]
    _grade_accounts(service_root, branch["accounts"], host, domain, host)


@pytest.mark.parametrize(
    "cert", _cases(_PART2, "certificates"), ids=lambda c: f"{c['amountMsat']}msat@{c['domain']}"
)
def test_part2_certificate(cert):
    vectors = load_vectors(_PART2)
    mint = vectors["mint"]
    mint_pubkey = mint["mintPubkey"]
    mint_key = PrivateKey(bytes.fromhex(mint["privateKey"]))
    assert mint_key.public_key.format(compressed=True).hex() == mint_pubkey

    # Every note in the file by key, so each certificate is checked the way a
    # recipient checks one: from the note's ck1 and its domain, nothing else.
    ck1_of = {
        n["notePubkey"]: (n["ck1"], b["domain"])
        for b in vectors["branches"]
        for n in _all_notes(b["accounts"])
    }

    pubkey, domain, amount = cert["notePubkey"], cert["domain"], cert["amountMsat"]
    assert note_signature_message_for_hash(pubkey, domain, amount) == cert["message"]
    digest = note_signature_digest_for_hash(pubkey, domain, amount)
    assert digest.hex() == cert["digest"]
    ck1, note_domain = ck1_of[pubkey]
    assert note_signature_message(ck1, domain, amount) == cert["message"]
    assert note_signature_digest(ck1, domain, amount) == digest

    signature = bytes.fromhex(cert["signature"])
    # RFC6979 on the mint's side too: its key over the digest reproduces the
    # certificate
    assert mint_key.sign_recoverable(digest, hasher=None) == signature
    assert encode_cs1_with_amount(amount, signature) == cert["cs1"]
    assert decode_cs1_with_amount(cert["cs1"]) == Cs1(amount, signature)
    assert is_cs1_with_amount(cert["cs1"])
    assert not is_cs1(cert["cs1"])
    assert decode_any_cs1(cert["cs1"]) == signature
    assert is_any_cs1(cert["cs1"])

    legacy = encode_cs1(signature)
    assert decode_cs1(legacy) == signature and is_cs1(legacy)
    assert decode_cs1_with_amount(legacy) is None and not is_cs1_with_amount(legacy)
    assert decode_any_cs1(legacy) == signature and is_any_cs1(legacy)
    recovered = PublicKey.from_signature_and_message(signature, digest, hasher=None)
    assert recovered.format(compressed=True).hex() == mint_pubkey

    # Recovers to the mint's key by the note's id at the certificate's domain,
    # and nowhere else. A current certificate is a cs1, never raw hex.
    assert verify_note_signature_hash(pubkey, domain, amount, cert["cs1"], mint_pubkey)
    assert not verify_note_signature_hash(pubkey, domain, amount, cert["signature"], mint_pubkey)
    assert not verify_note_signature_hash(pubkey, "elsewhere.example", amount, cert["cs1"], mint_pubkey)
    cp1 = encode_cp1(bytes.fromhex(pubkey))
    assert (
        check_note_certificate(cp1, domain, amount, cert["cs1"], mint_pubkey)
        is Certification.CERTIFIED_OVER_Q
    )
    assert not check_note_certificate(cp1, "elsewhere.example", amount, cert["cs1"], mint_pubkey)

    # A certificate for another domain than the note's own vouches for nothing
    # there.
    if domain != note_domain:
        assert not verify_note_signature(ck1, note_domain, amount, cert["cs1"], mint_pubkey)
        return
    assert (
        verify_note_signature(ck1, domain, amount, cert["cs1"], mint_pubkey)
        is Certification.CERTIFIED_OVER_Q
    )
    # ...and to nothing it does not cover
    assert not verify_note_signature(ck1, domain, amount + 1, cert["cs1"], mint_pubkey)
    other, other_domain = next(v for k, v in ck1_of.items() if k != pubkey)
    assert not verify_note_signature(other, other_domain, amount, cert["cs1"], mint_pubkey)
    # A cs1 whose prefix states another amount than the one it signs proves
    # nothing, whichever amount is asked about.
    relabelled = encode_cs1_with_amount(amount + 1000, signature)
    assert not verify_note_signature_hash(pubkey, domain, amount, relabelled, mint_pubkey)
    assert not verify_note_signature_hash(pubkey, domain, amount + 1000, relabelled, mint_pubkey)

    # The certificate is public, and so is Q. A ck1 pairing them with a
    # signature that does not open the note must not pass as the note, however
    # good the certificate; and the genuine ck1 is refused at any other mint.
    forged = bytearray(decode_ck1(ck1))
    forged[40] ^= 0x01
    assert not verify_note_signature(
        encode_ck1(bytes(forged)), domain, amount, cert["cs1"], mint_pubkey
    )
    assert not verify_note_signature(ck1, "elsewhere.example", amount, cert["cs1"], mint_pubkey)


def test_part2_legacy_certificates_are_read_and_reported_as_legacy():
    vectors = load_vectors(_PART2)
    mint_pubkey = vectors["mint"]["mintPubkey"]
    ck1_of = {
        n["notePubkey"]: (n["ck1"], b["domain"])
        for b in vectors["branches"]
        for n in _all_notes(b["accounts"])
    }
    legacy = vectors["legacyCertificates"]
    assert legacy
    for cert in legacy:
        pubkey, amount, cs1 = cert["notePubkey"], cert["amountMsat"], cert["cs1"]
        assert legacy_note_signature_message_for_hash(pubkey, amount) == cert["message"]
        assert legacy_note_signature_digest_for_hash(pubkey, amount).hex() == cert["digest"]
        assert verify_legacy_note_signature_hash(pubkey, amount, cs1, mint_pubkey)
        # ...and never as the current one
        assert not verify_note_signature_hash(pubkey, "mint.example", amount, cs1, mint_pubkey)
        ck1, domain = ck1_of[pubkey]
        assert (
            verify_note_signature(ck1, domain, amount, cs1, mint_pubkey)
            is Certification.CERTIFIED_OVER_LEGACY_Q
        )
        # raw hex is a legacy spelling too
        assert verify_legacy_note_signature_hash(pubkey, amount, cert["signature"], mint_pubkey)


@pytest.mark.parametrize(
    "proof",
    _cases(_PART2, "addressProofs"),
    ids=lambda p: f"{p.get('role', p['action'])}/{p['domain']}/{p['username']}",
)
def test_address_proof(proof):
    vectors = load_vectors(_PART2)
    share_key = {
        s["cx1"]: bytes.fromhex(s["sharePrivateKey"])
        for b in vectors["branches"]
        for a in b["accounts"]
        for s in a["shares"]
    }
    action, domain, username = proof["action"], proof["domain"], proof["username"]
    cx1, signer = proof.get("cx1"), proof["signerCx1"]
    secret = share_key[signer]
    assert _x_only(secret) == proof["signerPubkey"]
    # the mint's own domain, however the caller happens to spell it
    for spelling in (domain, domain.upper(), f"https://{domain}/w"):
        assert address_proof_message(action, spelling, username, cx1) == proof["message"]
    digest = address_proof_digest(action, domain, username, cx1)
    assert digest.hex() == proof["digest"]
    assert digest == hashlib.sha256(proof["message"].encode("utf-8")).digest()
    signature = sign_address_proof(secret, action, domain, username, cx1)
    assert signature.hex() == proof["signature"]

    # what the SERVICE checks: BIP-340 against x(P) of the signer's cx1
    assert verify_address_proof(signer, signature, action, domain, username, cx1)
    # bound to its domain, its signer and, where there is one, its cx1
    assert not verify_address_proof(
        signer, signature, action, "elsewhere.example", username, cx1
    )
    other = next(key for key in share_key if key not in (signer, cx1))
    assert not verify_address_proof(other, signature, action, domain, username, cx1)
    if cx1 is not None:
        assert not verify_address_proof(signer, signature, action, domain, username, other)


def test_address_proofs_cover_register_update_unregister_and_more_than_one_mint():
    proofs = _cases(_PART2, "addressProofs")
    assert {p["action"] for p in proofs} == {"register", "update", "unregister"}
    assert len({p["domain"] for p in proofs}) >= 2
    # a username is signed in lowercase
    assert any(p["username"] != p["username"].lower() for p in proofs)


def test_address_proof_refuses_what_it_cannot_bind():
    vectors = load_vectors(_PART2)
    cx1 = vectors["branches"][0]["accounts"][0]["shares"][0]["cx1"]
    legacy_cx1 = vectors["legacy"]["branches"][0]["cx1"]
    for action, bound in (
        ("register", None),
        ("update", None),
        ("unregister", cx1),
        ("delete", cx1),
        ("register", legacy_cx1),
        ("register", "not a cx1"),
    ):
        with pytest.raises(ProtocolError):
            address_proof_message(action, "mint.example", "alice", bound)
        with pytest.raises(ProtocolError):
            address_proof_digest(action, "mint.example", "alice", bound)
    with pytest.raises(ProtocolError):
        address_proof_message("register", "", "alice", cx1)
    with pytest.raises(ProtocolError):
        address_proof_message("unregister", "mint.example", " ", None)
    with pytest.raises(ProtocolError):
        sign_address_proof(bytes(32), "unregister", "mint.example", "alice")
    # a verifier never raises: malformed is simply not verified
    assert not verify_address_proof("not a cx1", bytes(64), "unregister", "mint.example", "alice")
    assert not verify_address_proof(cx1, b"short", "unregister", "mint.example", "alice")
    assert not verify_address_proof(cx1, bytes(64), "delete", "mint.example", "alice")
    assert not verify_address_proof(cx1, None, "unregister", "mint.example", "alice")


def _legacy_seed(branch: dict) -> bytes:
    return _bip39_seed(branch["mnemonic"])


def test_legacy_tweak_vectors():
    """The tweak schemes before LUD-26, kept so a wallet can find and sweep the
    notes it holds under them."""
    legacy = load_vectors(_PART2)["legacy"]
    assert legacy["superseded"] is True
    branches = legacy["branches"]
    assert any(b["branchParity"] == "odd" for b in branches)
    assert any(b["branchParity"] == "even" for b in branches)

    for branch in branches:
        host = branch["host"]
        root = derive_cash_root(_legacy_seed(branch))
        node = legacy_branch_node(root, host)
        assert cash_node_to_hex(node) == branch["addressNode"], host
        prefix = PrivateKey(node.private_key).public_key.format(compressed=True)[0]
        assert ("even" if prefix == 0x02 else "odd") == branch["branchParity"], host
        cx1 = legacy_cx1_of(node)
        assert cx1.pubkey_x_only.hex() == branch["branchPubkey"], host
        assert cx1.chain_code.hex() == branch["chainCode"], host
        assert encode_legacy_cx1(cx1) == branch["cx1"], host
        assert decode_legacy_cx1(branch["cx1"]) == cx1, host
        assert decode_cx1(branch["cx1"]) is None, f"{host}: no longer a cx1"

        notes = [(n["purpose"], n) for n in branch["notes"]]
        notes += [(None, n) for n in branch["prePurpose"]]
        assert {purpose for purpose, _ in notes} >= {None, 0, 1, 2}
        for purpose, note in notes:
            index = note["index"]
            at = f"{host} {purpose}/{index}"
            pk = legacy_derive_note_pubkey(cx1, purpose, index)
            assert pk.hex() == note["notePubkey"], at
            assert encode_cp1(pk) == note["cp1"], at
            sk = legacy_derive_note_secret_key(node, purpose, index)
            assert sk.hex() == note["noteSecretKey"], at
            assert _x_only(sk) == note["notePubkey"], at


@pytest.mark.parametrize(
    "case", _cases(_PART2, "valid"), ids=lambda c: f"{c['type']}: {c['why']}"
)
def test_part2_accepts(case):
    decoded = _PART2_DECODERS[case["type"]](case["value"])
    assert decoded is not None and decoded.hex() == case["bytes"]
    assert _PART2_TESTS[case["type"]](case["value"]) is True


@pytest.mark.parametrize(
    "case", _cases(_PART2, "invalid"), ids=lambda c: f"{c['type']}: {c['why']}"
)
def test_part2_refuses(case):
    assert case["why"]
    assert _PART2_DECODERS[case["type"]](case["value"]) is None
    assert _PART2_TESTS[case["type"]](case["value"]) is False


# ---- a Part 2 branch rooted in a Nostr key ----
#
# nostr-seed.json is an extension, not LUD-25/26, and says so. heartwood-esp32
# derives the same tree on the device, so the two have to agree on every value
# from one identity key or its notes do not come back from the nsec.


def test_nostr_seed_is_marked_as_an_extension():
    spec = load_vectors("nostr-seed.json")
    assert spec["extension"] is True
    assert spec["label"] == NOSTR_CASH_SEED_LABEL


@pytest.mark.parametrize(
    "case",
    _cases("nostr-seed.json", "cases"),
    ids=lambda c: f"{c['identityPubkey'][:8]}/{c['host']}",
)
def test_nostr_seed(case):
    identity = bytes.fromhex(case["identity"])
    host, domain = case["host"], case["domain"]
    assert spend_domain_of(host) == domain
    # the key the lightning address's npub encodes
    assert _x_only(identity) == case["identityPubkey"]

    seed = derive_nostr_cash_seed(identity)
    assert seed.hex() == case["seed"]
    root = derive_nostr_service_root(identity, host)
    assert cash_node_to_hex(root) == case["serviceRoot"]
    # nothing but LUD-26's tree from that seed
    assert cash_node_to_hex(derive_service_root(derive_cash_root(seed), host)) == case["serviceRoot"]
    assert case["accounts"]
    _grade_accounts(root, case["accounts"], host, domain, host)


# ---- LUD-25 and LUD-26's own published Test Vectors ----
#
# spec-vectors.json transcribes the vector files the specs publish (lnurl/luds
# 92e430f: 25-vectors.json and 26-vectors.json), so every value here is what
# the spec documents themselves publish, not just this project's own
# internally generated fixtures. Checked against the library's real functions.

_SPEC = "spec-vectors.json"
_CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _grade_spec_key_path_spend(spend: dict, secret: bytes, at: str) -> str:
    """A key_path_spend vector, both specs' shape. Returns its ck1."""
    q = bytes.fromhex(spend["Q"])
    assert PrivateKey(secret).public_key_xonly.format() == q, at
    assert encode_cp1(q) == spend["cp1"], at
    domain = spend["domain"]
    assert spend_prevout(domain).hex() == spend["prevout_txid"], at
    assert spend["spent_script_pubkey"] == "5120" + spend["Q"], at
    # every SigMsg field, in order, is exactly the whole SigMsg
    fields = spend["sigmsg_fields"]
    order = [
        "hash_type", "nVersion", "nLockTime", "sha_prevouts", "sha_amounts",
        "sha_scriptpubkeys", "sha_sequences", "sha_outputs", "spend_type", "input_index",
    ]
    assert list(fields) == order, at
    assert "".join(fields[name] for name in order) == spend["sigmsg"], at
    sig_msg = spend_sig_msg(q, domain, 0, 0xFFFFFFFF)
    assert sig_msg.hex() == spend["sigmsg"], at
    assert len(sig_msg) == 174, at
    assert key_path_sighash(q, domain).hex() == spend["sighash"], at
    assert spend["aux_rand"] == "00" * 32, at
    payload = sign_note_ownership(secret, domain)
    assert payload[:32] == q, at
    assert payload[32:].hex() == spend["sig"], at
    assert encode_ck1(payload) == spend["ck1"], at
    # the canonical spend transaction, serialised here with its witness rather
    # than by the library: version, segwit marker and flag, one input spending
    # (prevout, 0) with an empty scriptSig and a final sequence, one empty
    # zero-value output, the witness [sig], locktime 0
    tx = (
        "02000000" + "0001" + "01" + spend["prevout_txid"] + "00000000" + "00" + "ffffffff"
        + "01" + "0000000000000000" + "00" + "01" + "40" + spend["sig"] + "00000000"
    )
    assert tx == spend["spend_tx"], at
    assert note_id_of(spend["ck1"]) == spend["Q"], at
    verified = verify_spend(spend["ck1"], domain)
    assert verified is not None and verified.output_key == q and not verified.legacy, at
    # "The same ck1 submitted to a SERVICE on any other domain fails"
    assert verify_spend(spend["ck1"], "elsewhere.example") is None, at
    return spend["ck1"]


def test_lud25_spec_vectors():
    v = load_vectors(_SPEC)["lud25"]
    spend = v["key_path_spend"]
    ck1 = _grade_spec_key_path_spend(spend, bytes.fromhex(spend["sk"]), "lud25 key_path_spend")

    certificates = v["certificates"]
    mint_key = PrivateKey(bytes.fromhex(certificates["service_sk"]))
    mint_pubkey = mint_key.public_key.format(compressed=True).hex()
    assert mint_pubkey == certificates["mintPubkey"]
    q, domain = certificates["Q"], certificates["domain"]
    assert q == spend["Q"]
    for cert in certificates["cases"]:
        amount = cert["amount_msat"]
        assert note_signature_message_for_hash(q, domain, amount) == cert["message"], amount
        digest = note_signature_digest_for_hash(q, domain, amount)
        assert digest.hex() == cert["digest"], amount
        signature = mint_key.sign_recoverable(digest, hasher=None)
        assert signature.hex() == cert["signature"], amount
        cs1 = encode_cs1_with_amount(amount, signature)
        assert cs1 == cert["cs1"], amount
        assert verify_note_signature_hash(q, domain, amount, cs1, mint_pubkey), amount
        cp1 = encode_cp1(bytes.fromhex(q))
        assert (
            check_note_certificate(cp1, domain, amount, cs1, mint_pubkey)
            is Certification.CERTIFIED_OVER_Q
        )
        assert (
            verify_note_signature(ck1, spend["domain"], amount, cs1, mint_pubkey)
            is Certification.CERTIFIED_OVER_Q
        ), amount
        assert not verify_note_signature(ck1, "moneyer.dev", amount, cs1, mint_pubkey), amount

    # a bearer note, from preimage to cw1 and its certificate
    b = v["bearer_note"]
    preimage = bytes.fromhex(b["preimage"])
    h = hashlib.sha256(preimage).digest()
    assert h.hex() == b["h"] and hash_k1(b["preimage"]) == b["h"]
    leaf = bearer_leaf(h)
    assert leaf.hex() == b["leaf"]
    leaf_hash = tap_leaf_hash(leaf)
    assert leaf_hash.hex() == b["tapleaf_hash"]
    assert NUMS_KEY.hex() == b["H"]
    # t, independently: tagged_hash("TapTweak", H || tapleaf_hash)
    tag = hashlib.sha256(b"TapTweak").digest()
    assert hashlib.sha256(tag + tag + NUMS_KEY + leaf_hash).hexdigest() == b["tweak"]
    note = bearer_note(h)
    assert note.output_key.hex() == b["Q"]
    assert note.control_block.hex() == b["control_block"]
    assert encode_cp1(note.output_key) == b["cp1"]
    # "the hex h and cp1<Q> name the same note"
    assert bearer_note_id(b["h"]) == b["Q"]
    assert bearer_cw1(b["preimage"]) == b["cw1"]
    # "the hex preimage and the full cw1 are the same spend", and open Q at any
    # domain, since the leaf checks no signature
    for spend_k1 in (b["preimage"], b["cw1"]):
        for spend_domain in ("mint.example", "moneyer.dev"):
            verified = verify_spend(spend_k1, spend_domain)
            assert verified is not None and verified.output_key == note.output_key
            assert not verified.legacy and not verified.unevaluated
        assert note_id_of(spend_k1) == b["Q"]
    assert note_lookup_of(b["preimage"]) == b["h"]
    assert note_lookup_of(b["cw1"]) == b["cp1"]

    cert = b["certificate"]
    amount = cert["amount_msat"]
    url = b["note_url"]
    domain = spend_domain_of(url)
    assert note_signature_message(b["preimage"], url, amount) == cert["message"]
    digest = note_signature_digest(b["preimage"], url, amount)
    assert digest.hex() == cert["digest"]
    signature = mint_key.sign_recoverable(digest, hasher=None)
    assert signature.hex() == cert["signature"]
    cs1 = encode_cs1_with_amount(amount, signature)
    assert cs1 == cert["cs1"]
    for spend_k1 in (b["preimage"], b["cw1"]):
        assert (
            verify_note_signature(spend_k1, domain, amount, cs1, mint_pubkey)
            is Certification.CERTIFIED_OVER_Q
        )
        # the spend opens Q anywhere, but the certificate names one mint
        assert not verify_note_signature(spend_k1, "moneyer.dev", amount, cs1, mint_pubkey)
    for reference in (b["h"], b["cp1"]):
        assert (
            check_note_certificate(reference, domain, amount, cs1, mint_pubkey)
            is Certification.CERTIFIED_OVER_Q
        ), reference
    # the certified note, in short form, checked from its URL alone
    assert note_declared_amount(url) == amount
    assert verify_note_url(url, mint_pubkey) == (amount, Certification.CERTIFIED_OVER_Q)
    assert resolve_note_input(url) is not None


def test_lud26_spec_vectors():
    v = load_vectors(_SPEC)["lud26"]
    service_roots = []
    for dv in v["derivation"]:
        domain = dv["domain"]
        seed = bytes.fromhex(dv["seed"])
        root = derive_cash_root(seed)
        assert derive_cash_child(root, 0).private_key.hex() == dv["cashHashingKey"], domain
        assert list(cash_domain_indices(root, domain)) == dv["d"], domain
        service_root = derive_service_root(root, domain)

        def grade(path: NotePath, note: dict, at: str) -> None:
            key = derive_note_key(service_root, path)
            assert key.secret_key.hex() == note["sk"], at
            assert key.pubkey.hex() == note["pk"], at
            assert key.output_key.hex() == note["Q"], at
            assert encode_cp1(key.output_key) == note["cp1"], at

        for account in dv["accounts"]:
            a = account["account"]
            for note in account["wallet"]["notes"]:
                grade(NotePath.wallet(a, note["i"]), note, f"{domain} {a}'/0/{note['i']}")
            for note in account["change"]["notes"]:
                grade(NotePath.change(a, note["i"]), note, f"{domain} {a}'/1/{note['i']}")
            for share in account["shareable"]:
                n = share["share"]
                at = f"{domain} {a}'/2/{n}'"
                node = derive_share_node(service_root, a, n)
                assert node.private_key.hex() == share["p"], at
                assert node.chain_code.hex() == share["chaincode"], at
                cx1 = cash_node_to_cx1(node)
                assert cx1.pubkey.hex() == share["P"], at
                assert encode_cx1(cx1) == share["cx1"], at
                watched = decode_cx1(share["cx1"])
                assert watched == cx1, at
                for note in share["notes"]:
                    i = note["i"]
                    grade(NotePath.for_share(a, n, i), note, f"{at}/{i}")
                    assert derive_note_pubkey(watched, i).hex() == note["Q"], f"{at}/{i}: CKDpub"
        service_roots.append(service_root)

    # a key-path spend of an odd-y note: the signer negates the key
    spend = v["key_path_spend"]
    first = v["derivation"][0]["accounts"][0]["wallet"]["notes"][0]
    assert spend["path"] == first["path"]
    key = derive_note_key(service_roots[0], NotePath.wallet(0, 0))
    assert key.secret_key.hex() == spend["sk"]
    assert key.pubkey.hex() == spend["pk"]
    assert key.pubkey[0] == 0x03, "the vector's note has odd y"
    negated = (_CURVE_N - int.from_bytes(key.secret_key, "big")).to_bytes(32, "big")
    assert negated.hex() == spend["signing_sk"]
    _grade_spec_key_path_spend(spend, key.secret_key, "lud26 key_path_spend")

    # register share 0, update to share 1, unregister with share 1
    r = v["registration"]
    domain, username = r["domain"], r["username"]
    assert domain == v["derivation"][1]["domain"]
    account = v["derivation"][1]["accounts"][0]
    old = derive_share_node(service_roots[1], 0, 0)
    new = derive_share_node(service_roots[1], 0, 1)
    cx1, new_cx1 = r["cx1"], r["new_cx1"]
    assert cx1 == account["shareable"][0]["cx1"]
    assert new_cx1 == account["shareable"][1]["cx1"]
    for proof, action, bound, signer, signer_cx1 in (
        (r["register"], "register", cx1, old, cx1),
        (r["update"]["sig"], "update", new_cx1, old, cx1),
        (r["update"]["newsig"], "register", new_cx1, new, new_cx1),
        (r["unregister"], "unregister", None, new, new_cx1),
    ):
        assert address_proof_message(action, domain, username, bound) == proof["message"], action
        assert address_proof_digest(action, domain, username, bound).hex() == proof["digest"]
        signature = sign_address_proof(signer.private_key, action, domain, username, bound)
        assert signature.hex() == proof["sig"], action
        assert verify_address_proof(signer_cx1, signature, action, domain, username, bound), action
