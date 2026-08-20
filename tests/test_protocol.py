"""Runs against the conformance repo's mock mint - a real HTTP server that can
be told to misbehave. The happy paths matter, but the adversarial modes are
the reason this suite exists: a library that only works against a well-behaved
SERVICE has not been tested at all."""

from __future__ import annotations

import secrets as _secrets
import time

import pytest

from lnurlcash_kit import (
    AmbiguousMint,
    AmbiguousMutation,
    LnurlcashClient,
    NotePending,
    NoteSpent,
    NoteUnknown,
    ProtocolError,
    RequestRefused,
    ServiceRejected,
    build_note_url,
    hash_k1,
    verify_note_signature,
)


def secret() -> str:
    return _secrets.token_hex(32)


@pytest.fixture
def client() -> LnurlcashClient:
    return LnurlcashClient(timeout=10.0)


# ---- the informational GET ----


def test_reports_value_and_never_burns(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)

    info = client.fetch_note_info(m.note_url(k1))
    assert info.max_withdrawable == 21000
    assert info.k1 == k1
    assert m.note_state(k1) == "outstanding"

    assert client.fetch_note_info(m.note_url(k1)).max_withdrawable == 21000


def test_max_withdrawable_beats_the_urls_own_claim(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1, 2_100_000))
    assert info.max_withdrawable == 21000


def test_refuses_a_service_that_echoes_a_different_k1(mint, client):
    m = mint(echoWrongK1=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(ProtocolError):
        client.fetch_note_info(m.note_url(k1))


def test_unknown_and_spent_are_different_answers(mint, client):
    m = mint()
    known = secret()
    m.credit(known, 21000)
    with pytest.raises(NoteUnknown):
        client.fetch_note_info(m.note_url(secret()))

    info = client.fetch_note_info(m.note_url(known))
    client.rotate_note(info.callback, known)
    with pytest.raises(NoteSpent):
        client.fetch_note_info(m.note_url(known))


# ---- rotate ----


def test_rotate_burns_the_old_secret_and_mints_one_the_service_never_saw(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))

    rotated = client.rotate_note(info.callback, k1)
    assert rotated.k1 != k1
    assert m.note_state(k1) == "burned"
    assert m.note_state(rotated.k1) == "outstanding"
    assert client.fetch_note_info(m.note_url(rotated.k1)).max_withdrawable == 21000


def test_rotate_signature_verifies_offline(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)

    assert rotated.signature
    assert verify_note_signature(rotated.k1, 21000, rotated.signature, m.pubkey)
    assert not verify_note_signature(rotated.k1, 21001, rotated.signature, m.pubkey)


def test_accepts_the_other_recovery_id_layout(mint, client):
    m = mint(signatureLayout="leading")
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)
    assert verify_note_signature(rotated.k1, 21000, rotated.signature, m.pubkey)


def test_works_without_signatures(mint, client):
    m = mint(signatures=False)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)
    assert rotated.signature is None
    assert m.note_state(rotated.k1) == "outstanding"


def test_ignores_a_secret_the_service_tries_to_hand_back(mint, client):
    m = mint(serverGeneratedSecrets=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    rotated = client.rotate_note(info.callback, k1)
    # taking the mint's offered secret would hand it a permanent copy of the
    # note it just issued
    assert rotated.k1 != "a" * 64
    assert m.note_state(rotated.k1) == "outstanding"


# ---- split and merge ----


def test_split_produces_an_amount_and_its_change(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))

    result = client.split_note(info.callback, [k1], 5000)
    assert m.note_state(k1) == "burned"
    assert client.fetch_note_info(m.note_url(result.k1)).max_withdrawable == 5000
    assert client.fetch_note_info(m.note_url(result.change)).max_withdrawable == 16000
    assert verify_note_signature(result.k1, 5000, result.signature, m.pubkey)
    assert verify_note_signature(result.change, 16000, result.change_signature, m.pubkey)


def test_split_takes_several_notes_at_once(mint, client):
    m = mint()
    a, b = secret(), secret()
    m.credit(a, 21000)
    m.credit(b, 9000)
    info = client.fetch_note_info(m.note_url(a))

    result = client.split_note(info.callback, [a, b], 25000)
    assert m.note_state(a) == "burned"
    assert m.note_state(b) == "burned"
    assert client.fetch_note_info(m.note_url(result.k1)).max_withdrawable == 25000
    assert client.fetch_note_info(m.note_url(result.change)).max_withdrawable == 5000


def test_merge_sums(mint, client):
    m = mint()
    parts = [secret() for _ in range(3)]
    for i, k1 in enumerate(parts):
        m.credit(k1, 1000 * (i + 1))
    info = client.fetch_note_info(m.note_url(parts[0]))

    merged = client.merge_notes(info.callback, parts)
    for part in parts:
        assert m.note_state(part) == "burned"
    assert client.fetch_note_info(m.note_url(merged.k1)).max_withdrawable == 6000


def test_refuses_a_mutation_naming_no_note(mint, client):
    m = mint()
    with pytest.raises(RequestRefused):
        client.merge_notes(f"{m.url}/w/cb", [])
    with pytest.raises(RequestRefused):
        client.split_note(f"{m.url}/w/cb", [], 1000)


def test_settle_resolves_what_an_output_is_really_worth(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    result = client.split_note(info.callback, [k1], 5000)

    # the caller does not know the change is 16000 - only the service does
    settled_k1, amount, _sig, _cb = client.settle_note(
        m.note_url(k1), result.change, 0, result.change_signature
    )
    assert amount == 16000
    # and it was rotated on the way, so the GET-exposed secret is gone
    assert settled_k1 != result.change
    assert m.note_state(result.change) == "burned"


# ---- melt ----


def test_melt_ok_means_in_flight_not_spent(mint, client):
    m = mint(meltNeverSettles=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))

    result = client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")
    assert result.pr == "lnbc210n1pjqrstuvwxyz"
    assert m.note_state(k1) == "pending"


def test_pending_locks_out_other_operations(mint, client):
    m = mint(meltNeverSettles=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")

    with pytest.raises(NotePending):
        client.rotate_note(info.callback, k1)
    with pytest.raises(NotePending):
        client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")


def test_a_failed_melt_restores_the_note(mint, client):
    m = mint(meltAlwaysFails=True)
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")

    time.sleep(0.15)
    # a failed melt is never reported through the callback - it is only
    # observable as the note becoming spendable again
    assert m.note_state(k1) == "outstanding"
    assert client.fetch_note_info(m.note_url(k1)).max_withdrawable == 21000


def test_a_settled_melt_burns_the_note_and_proves_it(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    info = client.fetch_note_info(m.note_url(k1))
    result = client.melt_note(info.callback, k1, "lnbc210n1pjqrstuvwxyz")

    time.sleep(0.15)
    assert m.note_state(k1) == "burned"

    proof = client.fetch_invoice_verification(result.verify)
    assert proof.settled is True
    # the melt's preimage is not the note secret: the note that funded this
    # payment was already burned by the time the proof existed
    assert proof.preimage != k1


# ---- minting ----


def test_mints_a_note_from_a_paid_invoice_and_rotates_it(mint, client):
    m = mint()
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    assert pay.withdraw_link

    invoice = client.request_invoice(pay.callback, 21000)
    assert invoice.disposable is False
    assert invoice.verify

    payment_hash = invoice.verify.rsplit("/", 1)[-1]
    m.settle(payment_hash)

    verified = client.fetch_invoice_verification(invoice.verify)
    assert verified.settled is True
    # the preimage IS the note secret - which the mint necessarily saw
    claimed = verified.preimage
    assert hash_k1(claimed) == payment_hash

    info = client.fetch_note_info(build_note_url(pay.withdraw_link, claimed))
    assert info.max_withdrawable == 21000
    rotated = client.rotate_note(info.callback, claimed)
    # after rotating, the secret the mint generated is worthless
    assert m.note_state(claimed) == "burned"
    assert m.note_state(rotated.k1) == "outstanding"


def test_reads_an_advertised_fee(mint, client):
    m = mint(baseFeeMsat=1000, feePpm=2000)
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    assert pay.mint_fee.base_fee_msat == 1000
    assert pay.mint_fee.fee_ppm == 2000


def test_no_fee_advertised_means_fee_free(mint, client):
    m = mint()
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    assert pay.mint_fee is None


def test_a_fee_charging_mint_credits_the_net_amount(mint, client):
    m = mint(baseFeeMsat=1000, feePpm=2000)
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    invoice = client.request_invoice(pay.callback, 100000)
    payment_hash = invoice.verify.rsplit("/", 1)[-1]
    m.settle(payment_hash)
    claimed = client.fetch_invoice_verification(invoice.verify).preimage

    info = client.fetch_note_info(build_note_url(pay.withdraw_link, claimed))
    # 100000 - 1000 flat - 200 proportional
    from lnurlcash_kit import apply_mint_fee

    assert info.max_withdrawable == apply_mint_fee(100000, pay.mint_fee) == 98800


def test_finds_the_experimental_mint_address(mint, client):
    m = mint()
    address = client.fetch_mint_address(f"{m.url}/.well-known/lnurlw/mint")
    assert address.node_pubkey == m.pubkey
    assert address.pay_link.endswith("/.well-known/lnurlp/mint")


def test_reads_the_node_stats_a_mint_address_advertises(mint, client):
    m = mint()
    address = client.fetch_mint_address(f"{m.url}/.well-known/lnurlw/mint")
    # the wire field is nodeCapacity - renamed here, so it only arrives if it
    # is mapped rather than passed through under its own name
    assert address.node_capacity_msat == 500_000_000
    assert address.node_num_channels == 4
    assert address.node_num_peers == 6


def test_a_sunsetting_mint_refuses_definitively(mint, client):
    m = mint(sunset=True)
    pay = client.fetch_pay_request(f"{m.url}/.well-known/lnurlp/mint")
    with pytest.raises(ServiceRejected):
        client.request_invoice(pay.callback, 21000)


# ---- ambiguous outcomes ----


def test_a_lost_rotate_preserves_its_fresh_secret(mint, client):
    m = mint(dropAfterMutation=True)
    k1 = secret()
    m.credit(k1, 21000)

    with pytest.raises(AmbiguousMutation) as caught:
        client.rotate_note(f"{m.url}/w/cb", k1)
    assert len(caught.value.new_secrets) == 1

    # the mutation did land: the input is burned and the output exists, keyed
    # by the hash of a secret only the caller holds
    assert m.note_state(k1) == "burned"
    rescued = caught.value.new_secrets[0]
    assert m.note_state(rescued) == "outstanding"
    assert client.fetch_note_info(m.note_url(rescued)).max_withdrawable == 21000


def test_a_lost_split_preserves_both_secrets_in_output_order(mint, client):
    m = mint(dropAfterMutation=True)
    k1 = secret()
    m.credit(k1, 21000)

    with pytest.raises(AmbiguousMutation) as caught:
        client.split_note(f"{m.url}/w/cb", [k1], 5000)
    split_off, change = caught.value.new_secrets
    assert client.fetch_note_info(m.note_url(split_off)).max_withdrawable == 5000
    assert client.fetch_note_info(m.note_url(change)).max_withdrawable == 16000


def test_probing_resolves_the_ambiguity(mint, client):
    m = mint(dropAfterMutation=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(AmbiguousMutation):
        client.rotate_note(f"{m.url}/w/cb", k1)
    # gone: the burn landed, so the rescued secret is the only money left
    assert client.probe_burned_note(m.note_url(k1)) == "gone"

    live = mint()
    alive = secret()
    live.credit(alive, 21000)
    assert client.probe_burned_note(live.note_url(alive)) == "live"

    offline = LnurlcashClient(offline=True)
    assert offline.probe_burned_note(live.note_url(alive)) == "unknown"


def test_a_200_that_confirms_nothing_is_ambiguous(mint, client):
    m = mint(unconfirmedMutation=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(AmbiguousMutation):
        client.rotate_note(f"{m.url}/w/cb", k1)
    assert m.note_state(k1) == "burned"


def test_an_unreadable_response_is_ambiguous(mint, client):
    m = mint(malformedJson=True)
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(AmbiguousMutation):
        client.rotate_note(f"{m.url}/w/cb", k1)


def test_a_timeout_is_ambiguous_not_failure(mint):
    m = mint(slowMs=500)
    k1 = secret()
    m.credit(k1, 21000)
    impatient = LnurlcashClient(timeout=0.05)
    with pytest.raises(AmbiguousMutation):
        impatient.rotate_note(f"{m.url}/w/cb", k1)


def test_a_refused_request_is_definitely_not_sent(mint):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    offline = LnurlcashClient(offline=True)
    with pytest.raises(RequestRefused) as caught:
        offline.rotate_note(f"{m.url}/w/cb", k1)
    assert not isinstance(caught.value, AmbiguousMint)
    assert m.note_state(k1) == "outstanding"


def test_refuses_a_callback_url_it_would_not_fetch(mint, client):
    m = mint()
    k1 = secret()
    m.credit(k1, 21000)
    with pytest.raises(RequestRefused):
        client.rotate_note("http://evil.example/cb", k1)


# ---- a service that lies ----


def test_a_lying_service_cannot_inflate_past_what_it_signed(mint, client):
    m = mint(lieAboutValue=1_000_000)
    k1 = secret()
    signature = m.credit(k1, 21000)

    info = client.fetch_note_info(m.note_url(k1))
    assert info.max_withdrawable == 1_021_000
    # the signature was issued over the true amount, so the inflated one does
    # not verify - an offline holder catches this without asking anyone
    assert not verify_note_signature(k1, info.max_withdrawable, signature, m.pubkey)
    assert verify_note_signature(k1, 21000, signature, m.pubkey)
