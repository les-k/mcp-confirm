"""The ledger on its own, without a server or a protocol in the way."""

from __future__ import annotations

import pytest

from mcp_confirm.singleuse import Rejected, SingleUseLedger

NOW = 1_760_000_000


@pytest.fixture
def ledger() -> SingleUseLedger:
    return SingleUseLedger(ttl_seconds=300)


def test_an_issued_confirmation_can_be_spent_once(ledger: SingleUseLedger):
    nonce = ledger.issue(now=NOW)
    ledger.spend(nonce, now=NOW + 1)

    with pytest.raises(Rejected, match="already been used"):
        ledger.spend(nonce, now=NOW + 2)


def test_nonces_are_unique(ledger: SingleUseLedger):
    """Not for integrity — the SDK's envelope covers that — but so two
    confirmations outstanding at once cannot collide."""
    issued = {ledger.issue(now=NOW) for _ in range(200)}
    assert len(issued) == 200


def test_a_nonce_never_issued_is_refused(ledger: SingleUseLedger):
    with pytest.raises(Rejected, match="already been used, or was issued by a different"):
        ledger.spend("c-never-minted-this", now=NOW)


def test_an_empty_nonce_is_refused(ledger: SingleUseLedger):
    with pytest.raises(Rejected, match="no confirmation was supplied"):
        ledger.spend("", now=NOW)


def test_an_expired_confirmation_is_refused(ledger: SingleUseLedger):
    nonce = ledger.issue(now=NOW)
    with pytest.raises(Rejected, match="already been used|expired"):
        ledger.spend(nonce, now=NOW + 301)


def test_expiry_is_exclusive_at_the_boundary(ledger: SingleUseLedger):
    """A confirmation valid for one final instant is a race; the safe side of
    a boundary in a security check is the strict one."""
    good = ledger.issue(now=NOW)
    ledger.spend(good, now=NOW + 299)

    late = ledger.issue(now=NOW)
    with pytest.raises(Rejected, match="already been used|expired"):
        ledger.spend(late, now=NOW + 300)


def test_outstanding_confirmations_do_not_accumulate_forever(ledger: SingleUseLedger):
    """Retention is bounded by the TTL, not by count.

    An entry is only useful until the state it refers to would expire on its
    own; keeping it longer grows memory without buying any protection.
    """
    for _ in range(10):
        ledger.issue(now=NOW)
    assert ledger.outstanding() == 10

    ledger.issue(now=NOW + 1000)
    assert ledger.outstanding() == 1, "the sweep should have dropped the ten expired entries"


def test_spending_one_confirmation_does_not_invalidate_another(ledger: SingleUseLedger):
    first = ledger.issue(now=NOW)
    second = ledger.issue(now=NOW)

    ledger.spend(first, now=NOW + 1)
    ledger.spend(second, now=NOW + 1)  # must still work


@pytest.mark.parametrize("ttl", [0, -1, -300])
def test_a_non_positive_ttl_is_refused(ttl: int):
    with pytest.raises(Rejected, match="ttl_seconds must be positive"):
        SingleUseLedger(ttl_seconds=ttl)
