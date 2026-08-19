"""Every assertion here comes from lnurlcash-conformance. Nothing in this file
states what the protocol is - the vectors do, and this suite only binds them
to the library's functions."""

from __future__ import annotations

import pytest

from conftest import load_vectors
from lnurlcash_kit import (
    MintFee,
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


# ---- signatures ----


@pytest.mark.parametrize("case", _cases("signature.json", "cases"), ids=lambda c: c["name"])
def test_signature_verification(case):
    assert (
        verify_note_signature(
            case["k1"], case["amountMsat"], case["signature"], case["mintPubkey"]
        )
        is case["valid"]
    )


@pytest.mark.parametrize(
    "case",
    [c for c in _cases("signature.json", "cases") if c["message"] is not None],
    ids=lambda c: c["name"],
)
def test_signature_digest_derivation(case):
    assert note_signature_message(case["k1"], case["amountMsat"]) == case["message"]
    assert note_signature_digest(case["k1"], case["amountMsat"]).hex() == case["digest"]


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
    return MintFee(base_fee_msat=raw["baseFeeMsat"], fee_ppm=raw["feePpm"])


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
